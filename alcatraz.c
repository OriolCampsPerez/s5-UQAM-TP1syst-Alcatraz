/*  INF3173 - TP0
 *  Session : automne 2021
 *  Tous les groupes
 *
 *  IDENTIFICATION.
 *
 *      Nom : Camps Pérez
 *      Prénom : Oriol
 *      Code permanent : CAMO93010104
 *      Groupe : 30
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/prctl.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>



#define NB_CALLSYS_LNX 393 //nombre d'appels système en Linux (https://research.cs.queensu.ca/home/cordy/Papers/BKBHDC_ESE_Linux.pdf)
#define X32_SYSCALL_BIT 0x40000000
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

//  ***** fonctions utilisées *****  //
int count_nb(char *str);
static int install_filter(int syscall_nr, int t_arch, int f_errno);
static int install_multi_forbid_filters(int *syscall_tab, int nb_syscalls);
//  ** ** ***** *** *** ***** ** **  //


int main(int argc, char **argv){
  if (argc != 3) {
    return 1;
  }

  int pid = fork();
  if (pid<0) {
    // erreur fork --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
    return 1;
  }
  else if (pid==0) { // fils
    // s'assurer qu'aucune élévation de privilèges n'est faite dans le processus enfant, en utilisant l'appel système prctl;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
      // erreur prctl --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
      return 1;
    }

    // extraire les numéros des appels système à interdire;
    char param_restrictions[strlen(argv[1])];
    strncpy(param_restrictions,argv[1],strlen(argv[1]));

    int i = 0;
    char * fbn_syscall_str;
    int fbn_syscall_tab[NB_CALLSYS_LNX];
    int nb_nombres = count_nb(param_restrictions);

    fbn_syscall_str = strtok(param_restrictions, ",");
    fbn_syscall_tab[i] = atoi(fbn_syscall_str);
    ++i;


    while (i<nb_nombres) {
      fbn_syscall_str = strtok(NULL, ",");
      fbn_syscall_tab[i] = atoi(fbn_syscall_str);
      ++i;
    }

    // pour chaque numéro nr extrait installer un filtre pour l'interdire avec, encore une fois, l'appel système prctl;
    // man seccomp(2) utilisé

    if (install_multi_forbid_filters(fbn_syscall_tab,i) != 0) {
      // erreur install_multi_forbid_filters -- qui provient d'un erreur d'un appel système ; donc :
      // erreur --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
      return 1;
    }
    // install_filter(fbn_syscall_tab[0], AUDIT_ARCH_X86_64, 3253);

    // une fois les filtres en place, lancer LIGNE_COMMANDES avec l'appel système execve.
    // man execve(2) utilisé

    char *exec_args[] = {NULL, argv[2], NULL};
    char *environ[] = {NULL};
    execve(argv[2],exec_args,environ);
    // erreur execve --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
    return 1;

  }
  else { // père
    int wstatus;
    int wpidreturn = waitpid(pid,&wstatus,0);

    if (wpidreturn==pid) {
      if (WIFEXITED(wstatus)) {
        // succès --> 'Si le fils s'est terminé normalement, afficher la valeur retournée par le fils et terminer en retournant 0.'
        fprintf(stdout, "%d\n", WEXITSTATUS(wstatus));
        return 0;
      }
      else if (WIFSIGNALED(wstatus)) {
        // erreur --> 'Si le fils s'est terminé à cause d'un signal reçu, afficher le numéro du signal et retourner la valeur 1.'
        fprintf(stdout, "%d\n", WTERMSIG(wstatus));
        return 1;
      }
    }
    else {
      // erreur --> 'Dans tous les autres cas, ne rien afficher et retourner la valeur 0.'
      return 0;
    }
  }

    return 0;
}


/* fonction : int count_nb(char *str)
 * *str : chaine de caractères qui contient la liste des nombres des appels système à separer
 * sortie --> le nombre de nombres qu'il y a dans la liste
 */
int count_nb(char *str) {
  int i=0;
  int r=0;
  while (str[i]!='0') {
    if (str[i] == ',') {
      r++;
    }
    i++;
  }
  return r+1;
}

/* fonction : static int install_filter(int syscall_nr, int t_arch, int f_errno)
 *******************************************************************************
 * CETTE FONCTION APPARAÎT DANS LA SECTION EXEMPLES DE LA PAGE SECCOMP(2) DU MANUEL LINUX ; DISPONIBLE AVEC LA COMMANDE 'man seccomp.2'
 * --> 'Il est fortement recommandé de lire la documentation de l'appel système seccomp (notamment les exemples).'
 * elle a été modifié afin de l'adapter à ce TP
 *******************************************************************************
 * syscall_nr : le numéro d'appel système
 * t_arch : l'architecture choisie
 * f_errno : la valeur choisie pour mettre dans errno
 * sortie --> 0 si succès, 1 si erreur
 */
static int install_filter(int syscall_nr, int t_arch, int f_errno) {
  unsigned int upper_nr_limit = 0xffffffff;
  /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
   * (in the x32 ABI, all system calls have bit 30 set in the
   * 'nr' field, meaning the numbers are >= X32_SYSCALL_BIT).
   */
  if (t_arch == AUDIT_ARCH_X86_64) {
    upper_nr_limit = X32_SYSCALL_BIT - 1;
  }

  struct sock_filter filter[] = {
    // [0] Load architecture from 'seccomp_data' buffer into accumulator.
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),

    // [1] Jump forward 5 instructions if architecture does not match 't_arch'.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_arch, 0, 4),

    // [2] Load system call number from 'seccomp_data' buffer into accumulator.
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // [3] Check ABI - only needed for x86-64 in deny-list use cases. Use BPF_JGT instead of checking against the bit mask to avoid having to reload the syscall number.
    BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 3, 0),

    // [4] Jump forward 1 instruction if system call number does not match 'syscall_nr'.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1),

    // [5] Destination of architecture mismatch: kill process.
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    // [6] Destination of system call number mismatch: allow other system calls.
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // [7] Destination of architecture mismatch: kill process.
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };

  struct sock_fprog prog = {
    .len = ARRAY_SIZE(filter),
    .filter = filter,
  };

  //**** MODIFIÉ ****//
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    // erreur prctl --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
    return 1;
  }

  return 0;
}

/* fonction : static int install_multi_forbid_filters(int *syscall_tab, int nb_syscalls)
 * *syscall_tab : le tableau des entiers qui correspondent aux codes des appels système à interdire
 * nb_syscalls : la longueur du tableau *syscall_tab
 * sortie --> 0 si succès, 1 si erreur
 */
static int install_multi_forbid_filters(int *syscall_tab, int nb_syscalls) {
  for (int i=0 ; i<nb_syscalls ; i++) {
    if (install_filter(syscall_tab[i], AUDIT_ARCH_X86_64, 3253) != 0) {
      // erreur install_filter -- qui provient d'un erreur d'un appel système ; donc :
      // erreur --> 'Si un appel système fait par alcatraz, peu importe lequel, échoue, alors alcatraz doit s'arrêter et retourner la valeur 1.'
      return 1;
    }
  }
  return 0;
}
