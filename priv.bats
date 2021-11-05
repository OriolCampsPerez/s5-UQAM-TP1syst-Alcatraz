#!/usr/bin/env bats

load test_helper

@test "execve-1" {
    run ./alcatraz $(./ask-gcc open) ls 
    check 0 "1"
}

@test "execve-2" {
    run ./alcatraz $(./ask-gcc open) /bin/ls tests 
    checki 0 <<FIN
exit.c
nostart.c
0
FIN
}

@test "execve-3" {
    run ./alcatraz $(./ask-gcc open),$(./ask-gcc execve) /bin/ls tests 
    check 1 "31"
}

@test "ls" {
    run ./alcatraz $(./ask-gcc open),$(./ask-gcc openat) /bin/ls tests 
    check 1 "31"
}

@test "ls-1" {
    run ./alcatraz $(./ask-gcc open),$(./ask-gcc getdents) /bin/ls tests 
    checki 0 <<FIN
exit.c
nostart.c
0
FIN
}

@test "ls-2" {
    run ./alcatraz $(./ask-gcc open),$(./ask-gcc getdents64) /bin/ls tests 
    check 1 "31"
}

@test "ls-3" {
    run ./alcatraz $(./ask-gcc open),$(./ask-gcc getdents64) /bin/ls README.md 
    checki 0 <<FIN
README.md
0
FIN
}

@test "sudo" {
    run ./alcatraz $(./ask-gcc mkdir) /bin/bash -c "sudo head -n 1 /etc/shadow  | grep -o root"
    checki 0 <<FIN
root
0
FIN
}

@test "exit" {
    run gcc tests/exit.c -o tests/exit
    run ./alcatraz $(./ask-gcc exit) tests/exit
    checki 0 <<FIN
Nada!
0
FIN
}

@test "exit-1" {
    run ./alcatraz $(./ask-gcc exit),$(./ask-gcc _exit) tests/exit
    check 0 "1"
}

@test "exit-2" {
    run ./alcatraz $(./ask-gcc exit),$(./ask-gcc exit_group) tests/exit
    checki 1 <<FIN
Nada!
31
FIN
}
