/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright 2011, 2012, 2013, 2014 Big Switch Networks, Inc.
 * Copyright 2014 Skyport Systems, Inc.
 *
 * isolate: Run a command in a separate namespace, isolating network
 * and other system resources.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syscall.h>
#include <string.h>
#include <grp.h>
#include <sys/param.h>
#include <getopt.h>
#include <fcntl.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>

int main(int argc, char *argv[])
{
    char *cmd;
    char **args;
    int help_flag = 0;
    int as_root_flag = 0;
    int login_flag = 0;
    char *pre_script = "/usr/share/isolate/isolate-pre";
    char *child_script = "/usr/share/isolate/isolate-child";
    char *post_script = "/usr/share/isolate/isolate-post";
    char *chroot_arg = NULL;
    char *chdir_arg = NULL;
    int pid;
    int pf[2];

    /* Creating a new namespace via clone() requires CAP_SYS_ADMIN privilege,
       so re-exec the process with sudo if we're not already root */
    if (getuid() != 0) {
        char *a[argc + 3];
        a[0] = "sudo";
        a[1] = "-E";
        memcpy(&a[2], argv, argc * sizeof(char *));
        a[argc + 2] = NULL;
        execvp("sudo", a);
        perror("sudo");
        return 1;
    }

    while (1) {
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'
            },
            {"as-root", no_argument, NULL, 'r'
            },
            {"login", no_argument, NULL, 'l'
            },
            {"pre-script", required_argument, NULL, 'p'
            },
            {"child-script", required_argument, NULL, 'c'
            },
            {"post-script", required_argument, NULL, 't'
            },
            {"chroot", required_argument, NULL, 'o'
            },
            {"chdir", required_argument, NULL, 'd'
            },
            {0, 0, 0, 0
            }
        };
        int option_index = 0;
        int c = getopt_long(argc, argv, "+hrlp:c:t:o:d:", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 0:
            break;
        case 'h':
            help_flag = 1;
            break;
        case 'r':
            as_root_flag = 1;
            break;
        case 'l':
            login_flag = 1;
            break;
        case 'p':
            pre_script = optarg;
            break;
        case 'c':
            child_script = optarg;
            break;
        case 't':
            post_script = optarg;
            break;
        case 'o':
            chroot_arg = optarg;
            break;
        case 'd':
            chdir_arg = optarg;
            break;
        default:
            return 1;
        }
    }

    if (help_flag) {
        printf("Usage: %s [OPTIONS] [COMMAND]\n\n", argv[0]);
        printf("  Run COMMAND in a separate namespace, isolating network and other\n");
        printf("  system resources. Runs $SHELL if COMMAND is not specified.\n\n");
        printf("  Options:\n");
        printf("  -h|--help: Print this help message.\n");
        printf("  -p|--pre-script SCRIPT: Run SCRIPT in the parent process after\n");
        printf("         forking the child process.\n");
        printf("  -c|--child-script SCRIPT: Run SCRIPT in the child process before\n");
        printf("         executing the command.\n");
        printf("  -t|--post-script SCRIPT: Run SCRIPT in the parent process after\n");
        printf("         the child process terminates.\n");
        printf("  -r|--as-root: Run the command as root instead of SUDO_UID.\n");
        printf("  -l|--login: Prepend a dash to the command's argv[0].\n");
        printf("  -o|--chroot DIR: Run command with root directory set to DIR.\n");
        printf("  -d|--chdir DIR: Change to DIR before running command.\n");
        return 1;
    }

    if (optind < argc) {
        cmd = argv[optind];
        args = (char **) calloc(argc - optind + 1, sizeof(char *));
        memcpy(&args[0], &argv[optind], sizeof(char *) * (argc - optind + 1));
    } else {
        cmd = getenv("SHELL");
        if (!cmd)
            cmd = "/bin/bash";
        args = (char **) calloc(2, sizeof(char *));
        args[0] = cmd;
    }
    if (login_flag) {
        args[0] = (char *) malloc(strlen(cmd) + 2);
        args[0][0] = '-';
        strcpy(&args[0][1], cmd);
    }

    /* Create a pipe for the parent to tell child its pid */
    pipe(pf);

    /* Fork a child process with new namespaces */
    pid = syscall(SYS_clone, SIGCHLD | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS
                  | CLONE_NEWUTS | CLONE_NEWIPC, 0);
    if (pid < 0)
        error(1, errno, "clone");
    if (pid == 0) {
        /* Child process */
        char *sudo_uid, *sudo_gid, *sudo_user = NULL;
        gid_t *sudo_groups = NULL;
        int sudo_ngroups = 0;
        int i;
        /* Reopen stdin/out/err if they are ttys (otherwise fstat() can fail
           with EACCES, causing tcpdump to use buffered IO) */
        for (i = 0; i < 3; i++) {
            char *ttyi = ttyname(i);
            if (ttyi) {
                int j;
                close(i);
                open(ttyi, O_RDWR);
                /* If the same tty is shared, dup the fd: bash clears
                   O_NONBLOCK only on stdin if a child leaves it set, but we
                   need this behavior for stdout and stderr too to avoid
                   getting EAGAIN when a process dumps a lot of output */
                for (j = 0; j < i; j++) {
                    if (ttyname(j) && strcmp(ttyname(j), ttyname(i)) == 0) {
                        close(i);
                        dup(j);
                    }
                }
            }
        }
        close(pf[1]);
        /* Wait for the parent to tell us our pid */
        for (i = 0; i < (int) sizeof(pid); i++) {
            if (read(pf[0], ((char *) &pid) + i, 1) != 1)
                return 1;
        }
        close(pf[0]);
        signal(SIGINT, _exit);
        if (child_script) {
            /* Run the child setup script */
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s %d %s", child_script, pid,
                     chroot_arg ? chroot_arg : "/");
            if (system(p) != 0)
                return 1;
        }
        /* Figure out the pre-sudo user and group info before chrooting */
        sudo_uid = getenv("SUDO_UID");
        sudo_gid = getenv("SUDO_GID");
        sudo_user = getenv("SUDO_USER");
        if (sudo_user && sudo_gid) {
            gid_t gid = atoi(sudo_gid);
            getgrouplist(sudo_user, gid, NULL, &sudo_ngroups);
            if (sudo_ngroups > 0) {
                sudo_groups = malloc(sudo_ngroups * sizeof(gid_t));
                getgrouplist(sudo_user, gid, sudo_groups, &sudo_ngroups);
            }
        }
        if (chroot_arg)
            if (chroot(chroot_arg) != 0)
                error(1, errno, "chroot: %s", chroot_arg);
        if (chdir_arg)
            if (chdir(chdir_arg) != 0)
                error(1, errno, "chdir: %s", chdir_arg);
        if (!as_root_flag) {
            /* Reset user and group to their pre-sudo state */
            if (sudo_gid) {
                gid_t gid = atoi(sudo_gid);
                setgid(gid);
            }
            if (sudo_groups) {
                setgroups(sudo_ngroups, sudo_groups);
                free(sudo_groups);
            }
            if (sudo_uid) {
                uid_t uid = atoi(sudo_uid);
                setuid(uid);
            }
        }
        /* Exec the command */
        execvp(cmd, args);
        perror(cmd);
    } else {
        /* Parent process */
        int status;
        signal(SIGINT, SIG_IGN);
        close(pf[0]);
        if (pre_script) {
            /* Run the parent setup script */
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s %d %s", pre_script, pid,
                     chroot_arg ? chroot_arg : "/");
            if (system(p) != 0)
                return 1;
        }
        /* Tell the child what its pid is */
        write(pf[1], &pid, sizeof(pid));
        close(pf[1]);
        /* Wait for the child to finish, and return its exit code */
        waitpid(pid, &status, 0);
        if (post_script) {
            /* Run the parent cleanup script */
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s %d %s", post_script, pid,
                     chroot_arg ? chroot_arg : "/");
            if (system(p) != 0)
                return 1;
        }
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
    }
    return 1;
}
