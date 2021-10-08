# TP1 - Alcatraz

L'objectif du TP1 est de développer l'utilitaire `alcatraz` qui lance une ligne de commande avec une restriction sur les appels système.

## Avant de commencer

* Cloner (le bouton `fork` en haut à droite) ce dépôt sur le gitlab départemental.
* Le rendre privé : dans `Settings` → `General` → `Visibility` → `Project visibility` → `Private` (n'oubliez pas d'enregistrer).
* Ajouter l'utilisateur `@abdenbi_m` comme mainteneur (oui, j'ai besoin de ce niveau de droits) : dans `Settings` → `Members` → `Invite member` → `@abdenbi_m`.
* ⚠️ Mal effectuer ces étapes vous expose à des pénalités importantes sans préavis.

## Description de l'outil

```
alcatraz nr[,nr...] LIGNE_COMMANDES
```
`alcatraz` prend 2 arguments :
- une liste non vide d'entiers séparés par une virgule (`,`), représentant des appels système,
- une ligne de commande _shell_ à exécuter.

`alcatraz` va créer un processus fils avec l'appel système `fork` et va effectuer les instructions/actions suivantes.
- Dans le processus fils :
  - s'assurer qu'aucune élévation de privilèges n'est faite dans le processus enfant, en utilisant l'appel système `prctl`;
  - extraire les numéros des appels système à interdire;
  - pour chaque numéro `nr` extrait installer un filtre pour l'interdire avec, encore une fois, l'appel système `prctl`;
  - une fois les filtres en place, lancer `LIGNE_COMMANDES` avec l'appel système `execve`.
- Dans le processus parent :
  - attendre la fin du fils avec l'appel système `waitpid`;
  - si le fils s'est terminé normalement, afficher la valeur retournée par le fils et terminer en retournant `0`;
  - si le fils s'est terminé à cause d'un signal reçu, afficher le numéro du signal et retourner la valeur `1`;
  - dans tous les autres cas, ne rien afficher et retourner la valeur `0`.

  <p>

<p>

<details>

<summary>Exemple</summary>

<pre>
<b>iam@groot:~/$</b> strace tests/nostart > /dev/null
execve("tests/nostart", ["tests/nostart"], 0x7ffdfb2aba00 /* 57 vars */) = 0
write(1, "Hello, World!\n", 14)         = 14
exit(0)                                 = ?
+++ exited with 0 +++
<b>iam@groot:~/$</b> ./alcatraz $(./ask-gcc read) tests/nostart
Hello, World!
0
<b>iam@groot:~/$</b> echo $?
0
<b>iam@groot:~/$</b> ./alcatraz $(./ask-gcc read),$(./ask-gcc exit) tests/nostart
Hello, World!
31
<b>iam@groot:~/$</b> echo $?
1
<b>iam@groot:~/$</b> ./alcatraz $(./ask-gcc read),$(./ask-gcc exit),$(./ask-gcc write) tests/nostart
31
<b>iam@groot:~/$</b> echo $?
1
</pre>

</details>

</p>

### Traitement des erreurs et valeur de retour

Si un appel système fait par `alcatraz`, peu importe lequel, échoue, alors `alcatraz` doit s'arrêter et retourner la valeur `1`. **Aucun message d'erreur ne doit être affiché**.

Si `LIGNE_COMMANDES` se termine à cause d'un signal reçu, la valeur `1` est retournée.

Dans tous les autres cas la valeur `0` est retournée.

## Directives d'implémentation

Vous devez développer le programme en C.
Le fichier source doit s'appeler `alcatraz.c` et être à la racine du dépôt.
Vu la taille du projet, tout doit rentrer dans ce seul fichier source.

Pour la réalisation du TP, vous devez respecter les directives suivantes.

### Appels système

- **Vous devez utiliser l'appel système** `execve` pour tout recouvrement. Aucune fonction de librairie parmi `execl`, `execlp`, `execle`, `execv`, `execvp` ou `execvpe` **n'est acceptée**.
- Vous devez utiliser l'appel système `prctl` pour installer les filtres.
- En plus des appels système cités plus haut, vous aurez besoin des appels système `fork` et `waitpid`.
- Noubliez pas de traiter les cas d'erreurs de vos appels système.

### Précisions

- Vous pouvez assumer que les arguments avec lesquels l'utilitaire `alcatraz` sera testé sont valides. C'est à dire,
  - `nr,...` sont des numéros d'appels système valides séparés, s'il y a lieu, par une virgule (`,`),
  - `LIGNE_COMMANDES` est une ligne de commandes valide (qui peut s'exécuter directement sur un _shell_).
- Pour mettre en place la protection contre l'élévation de privilèges, utilisez l'appel système `prctl` avec l'option `PR_SET_NO_NEW_PRIVS` et activer là avec le deuxième argument (`no_new_privs`) mis à `1`. Le reste des arguments sont ignorés et peuvent donc être initialisés à `0` (se référer au manuel de `prctl` pour plus de détails).
- Codez d'abord l'utilitaire `alcatraz` avec un seul appel système à interdire. Mettez les étapes de filtrage ci-bas dans une fonction pour faciliter sa réutilisation.
- Pour installer un filtre vous devez utiliser l'appel système `prctl` avec l'option `PR_SET_SECCOMP` et l'argument `SECCOMP_MODE_FILTER`.
  - Un **filtre** est une structure C de type `sock_fprog` qui pointe vers un ensemble d'instructions machine minimalistes, qui permettent de vérifier/filtrer, entre autre, les appels système. 
  Ces instructions sont regroupées dans la structure C `sock_filter` et seront injectées dans le noyau par `prctl`. 
  Ce format est appelé [Berkeley Packet Filter](https://fr.wikipedia.org/wiki/BSD_Packet_Filter). Une référence à la structure `sock_fprog` est donnée en troisième argument à `prctl`.
  - Pour construire votre structure `sock_filter` (vos instructions machine vous aurez besoin des macros `BPF_STMT` et `BPF_JUMP`.
  - L'ensemble des instructions machine (combinable avec des **ou binaires**) dont vous aurez besoin sont,
    - `BPF_L` pour charger des mots dans un registre,
    - `BPF_W` pour indiquer que c'est un mot mémoire qui sera chargé,
    - `BPF_ABS` pour indiqué un décalage (_offset_) fixe,
    - `BPF_JMP` combiné à `BPF_JEQ` pour vérifier une condition d'égalité (il existe aussi d'autres types de comparaisons),
    - `BPF_K` pour comparer à, ou utiliser, une constante,
    - `BPF_RET` combiné à `BPF_K` pour retourner une valeur. Pour un filtre d'appel système, vous retournez soit `SECCOMP_RET_ALLOW` pour autoriser un appel système, soit `SECCOMP_RET_KILL_PROCESS` pour l'interdire et tuer le processus appelant.
  - Votre structure `sock_filter` doit effectuer les vérifications suivantes,
    - charger l'architecture de la machine sur laquelle il roule et seule `AUDIT_ARCH_X86_64` est autorisée, autrement il retourne `SECCOMP_RET_KILL_PROCESS`,
    - charger l'appel système lancé par le processus appelant et le comparer avec un unique numéro d'appel système. S'ils sont égaux c'est un arrêt immédiat qui est retourné avec `SECCOMP_RET_KILL_PROCESS`, si non, l'appel système est autorisé avec `SECCOMP_RET_ALLOW`.
- Il est fortement recommandé de lire la documentation de l'appel système `seccomp` (notamment les exemples).
- Vous pouvez utiliser le script `ask-gcc` pour connaitre le numéro d'un appel système. Par exemple `./ask-gcc read` va afficher `0` ou `./ask-gcc write` va afficher `1`.
- Comme le TP n'est pas si gros, il est attendu un effort important sur le soin du code et la gestion des cas d'erreurs.

## Acceptation et remise du TP

### Remise

La remise s'effectue simplement en poussant votre code sur la branche `master` de votre dépôt gitlab privé.
Seule la dernière version disponible avant le **dimanche 24 octobre à 23h55** sera considérée pour la correction.


### Intégration continue

Vous pouvez compiler avec `make` (le `Makefile` est fourni).

Vous pouvez vous familiariser avec le contenu du dépôt, en étudiant chacun des fichiers (`README.md`, `Makefile`, `check.bats`, `.gitlab-ci.yml`, etc.).

⚠️ À priori, il n'y a pas de raison de modifier un autre fichier du dépôt.
Si vous en avez besoin, ou si vous trouvez des bogues ou problèmes dans les autres fichiers, merci de me contacter.

Le système d'intégration continue vérifie votre TP à chaque `push`.
Vous pouvez vérifier localement avec `make check` (l'utilitaire `bats` entre autres est nécessaire).

Les tests fournis ne couvrent que les cas d'utilisation de base, en particulier ceux présentés ici.
Il est **fortement suggéré** d'ajouter vos propres tests dans [local.bats](local.bats) et de les pousser pour que l’intégration continue les prenne en compte.
Ils sont dans un job distincts pour avoir une meilleure vue de l'état du projet.

❤ En cas de problème pour exécuter les tests sur votre machine, merci de 1. lire la documentation présente ici et 2. poser vos questions en classe ou sur [Mattermost](https://mattermost.info.uqam.ca/forum/channels/inf3173).
Attention toutefois à ne pas fuiter de l’information relative à votre solution (conception, morceaux de code, etc.)

### Barème et critères de correction

Le barème utilisé est le suivant

* Seuls les tests qui passent sur l'instance `gitlab.info.uqam.ca` (avec l'intégration continue) seront considérés.
  * 50%: pour le jeu de test public fourni dans le sujet (voir section intégration).
  * 50%: pour un jeu de test privé exécuté lors de la correction. Ces tests pourront être plus gros, difficiles et/ou impliquer des cas limites d'utilisation (afin de vérifier l'exactitude et la robustesse de votre code).
* Des pénalités pour des bogues spécifiques et des défauts dans le code source du programme, ce qui inclut, mais sans s'y limiter l'exactitude, la robustesse, la lisibilité, la simplicité, la conception, les commentaires, etc.
* Note: consultez la section suivante pour des exemples de pénalités et éventuellement des conseils pour les éviter.

## Mentions supplémentaires importantes

⚠️ **Intégrité académique**
Rendre public votre dépôt personnel ou votre code ici ou ailleurs ; ou faire des MR contenant votre code vers ce dépôt principal (ou vers tout autre dépôt accessible) sera considéré comme du **plagiat**.

⚠️ Attention, vérifier **=/=** valider.
Ce n'est pas parce que les tests passent chez vous ou ailleurs ou que vous avez une pastille verte sur gitlab que votre TP est valide et vaut 100%.
Par contre, si des tests échouent quelque part, c'est généralement un bon indicateur de problèmes dans votre code.

⚠️ Si votre programme **ne compile pas** ou **ne passe aucun test public**, une note de **0 sera automatiquement attribuée**, et cela indépendamment de la qualité de code source ou de la quantité de travail mise estimée.
Il est ultimement de votre responsabilité de tester et valider votre programme.

Pour les tests, autant publics que privés, les résultats qui font foi sont ceux exécutés sur l'instance `gitlab.info.uqam.ca`. Si un test réussi presque ou de temps en temps, il est considéré comme échoué (sauf rares exceptions).


Quelques exemples de bogues fréquents dans les copies TP de INF3173 qui causent une perte de points, en plus d'être responsable de tests échoués:

* Utilisation de variables ou de mémoire non initialisés (comportement indéterminé).
* Mauvaise vérification des cas d'erreur des fonctions et appels système (souvent comportement indéterminé si le programme continue comme si de rien n'était)
* Utilisation de valeurs numériques arbitraires (*magic number*) qui cause des comportements erronés si ces valeurs sont dépassées (souvent dans les tailles de tableau).
* Code inutilement compliqué, donc fragile dans des cas plus ou moins limites.


Quelques exemples de pénalités additionnelles:

* Vous faites une MR sur le dépôt public avec votre code privé : à partir de -10%
* Vous demandez à être membre du dépôt public : -5%
* Si vous critiquez à tort l'infrastructure de test : -10%
* Vous modifiez un fichier autre que le fichier source ou `local.bats` (ou en créez un) sans avoir l’autorisation : à partir de -10%
* Votre dépôt n'est pas un fork de celui-ci : -100%
* Votre dépôt n'est pas privé : -100%
* L'utilisateur `@abdenbi_m` n'est pas mainteneur : -100%
* Votre dépôt n'est pas hébergé sur le gitlab départemental : -100%
* Vous faites une remise par courriel : -100%
* Vous utilisez « mais chez-moi ça marche » (ou une variante) comme argument : -100%
* Si je trouve des morceaux de votre code sur le net (même si vous en êtes l'auteur) : -100%
