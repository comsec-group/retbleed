// SPDX-License-Identifier: GPL-3.0-only
#define _GNU_SOURCE
       #include <sys/stat.h>
#include <sched.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <getopt.h>
#include <string.h>

#include <fcntl.h>
#include <sys/types.h>
#include <err.h>

#include <unistd.h>

void usage() {
    printf("Usage: ./fg [-o tracer-log] -t tracer_path [-p cpu] [-h] PROG [ARGS]\n");
    exit(0);
}

#ifndef HAVE_PROGRAM_INVOCATION_NAME
extern char *program_invocation_name;
#endif

char buf[256];

void err_and_die(char *m) {
    fprintf(stderr, "%s: %s\n", program_invocation_name, m);
    kill(0, SIGINT);
    exit(1);
}

int main(int argc, char *argv[])
{
    int c;
    char *log_path = NULL;
    char *tracer_path = NULL;
 //   int fd_log;
    if (argc < 1) {
        usage();
    }

    // will use cpu 3 by default.
    int cpu = 3;

    while ((c = getopt(argc, argv, "ho:t:p:")) != -1) {
        switch (c) {
            case 'h':
                usage();
            case 'o':
                log_path = strdup(optarg);
                break;
            case 't':
                tracer_path = strdup(optarg);
                break;
            case 'p':
                cpu = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Try %s -h\n", program_invocation_name);
                exit(1);
        }
    }

    argc -= optind;
    argv += optind;
    if (argc <= 0) {
        err_and_die("must specify PROG [ARGS]");
    }

    if (!log_path) {
        err_and_die("must specify -o");
    }

    if (!tracer_path) {
        err_and_die("must specify -t");
    }

 //   if ((fd_log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
 //       err(2, "can't open logfile '%s'",log_path);
 //   }


    // start_child
    pid_t pid_test;
    pid_t pid_tracer;

    int pipe_test[2];
    if (pipe(pipe_test) < 0) {
        err(1, "pipe test");
    }

    char *test_args[5] = { NULL }; // up to 5 args in cmdline
    char *s = argv[0];
    for (int i = 0; s != NULL && i < 5; ++i) {
	    test_args[i] = s;
	    s = strstr(s, " ");
	    if (s) {
		    *s = '\0';
		    ++s;
	    }
    }

    fprintf(stderr, "test command: ");
    for (int i = 0 ; i <  5; ++i) {
        if(test_args[i] == NULL) break;
        fprintf(stderr, "%s ", test_args[i]);
    }
    fprintf(stderr,"\n");

    if ((pid_test = fork()) == 0) {
        char b;
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        sched_setaffinity(getpid(), sizeof(set), &set);
        close(pipe_test[1]); // close communication to parent
        read(pipe_test[0], &b, 1); // wait for tracer to be ready
        close(pipe_test[0]); // close communication from parent

        // to either split argv[1] into strings or just run it like this.
        if (execve(test_args[0], test_args, environ) != 0) {
            err(2,"exec %s", test_args[0]);
        }
        // unreachable
        exit(1);
    }

    close(pipe_test[0]);

    int pipe_tracer[2];
    if (pipe(pipe_tracer) < 0) {
        err(1, "pipe tracer");
    }

    char pidstr[12] = {0};
    sprintf(pidstr, "%d", pid_test);
    if ((pid_tracer = fork()) == 0) {
        close(pipe_tracer[0]);
        dup2(pipe_tracer[1], fileno(stdout));
        setuid(0);
        if (getuid() != 0 || geteuid() != 0) {
            // program needs cap_setuid to run..
            err_and_die("You must be root to trace");
        }

        char cpustr[5];
        sprintf(cpustr, "%d", cpu);

        // run the actual tracer here.. it will give lots of output
        if (execl("/usr/bin/sudo", "sudo", tracer_path, pidstr, log_path, cpustr, NULL) != 0) {
            err(2, "tracer failed");
        }
        // unreachable
        exit(1);
    }
    setpgid(pid_tracer, 0);

    // not going to write to tracer
    close(pipe_tracer[1]);
    fprintf(stderr, "Waiting for tracer to wakeup...");
    fflush(stderr);
    int r = 0;
    while ((r = read(pipe_tracer[0], buf, sizeof(buf))) > 0) {
        if (strstr(buf, "GO cpid=") != 0) {
            break;
        }
    }

    fprintf(stderr, "OK! now logging..\n");

    write(pipe_test[1], "0", 2);
    close(pipe_test[1]);
    int status = 0;
    waitpid(pid_test, &status, 0);

    // need to wait for log writing to finish reading..
    // need a way to find out that we've exhausted the buffer, this was the
    // ugliest i could come up with..
    // TODO: just forget about cat-ing in the sh script: mmap and read really
    // large chunks instead...
    setuid(0);
    int fd_t = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    while (1) {
        lseek(fd_t, 0, SEEK_SET);
        // the file contains only 27 bytes of data when empty
        if (read(fd_t, buf, 32) < 32) {
            break;
        }
        usleep(10000);
    }

    kill(-pid_tracer, SIGTERM);
    fprintf(stderr, "---------------Test finished %d-----------------\n",status);
    return 0;
}
