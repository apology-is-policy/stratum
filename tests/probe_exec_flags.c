/* Does a signal's SA_RESTART flag outlive an exec that resets its handler to the default?
 * The parent installs a handler for SIGUSR2 with or without SA_RESTART and execs itself;
 * the child prints what sigaction says of SIGUSR2. Usage: exec-flags */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void taken(int sig) { (void)sig; }

static void say(const char *what)
{
    struct sigaction act;
    struct utsname u;
    uname(&u);
    memset(&act, 0, sizeof act);
    sigaction(SIGUSR2, NULL, &act);
    printf("%s, %s: handler %s, sa_flags 0x%x, SA_RESTART %s\n", u.sysname, what,
           act.sa_handler == SIG_DFL ? "SIG_DFL" : act.sa_handler == SIG_IGN ? "SIG_IGN" : "a function",
           (unsigned)act.sa_flags, (act.sa_flags & SA_RESTART) ? "set" : "clear");
    fflush(stdout);
}

/* Every signal that did not reach this program at its default action with no flags. */
static void say_all(void)
{
    int n = 0;
    for (int sig = 1; sig < 32; sig++) {
        struct sigaction act;
        memset(&act, 0, sizeof act);
        if (sigaction(sig, NULL, &act) != 0 || (act.sa_handler == SIG_DFL && act.sa_flags == 0))
            continue;
        printf("  inherited: signal %d: handler %s, sa_flags 0x%x\n", sig,
               act.sa_handler == SIG_DFL ? "SIG_DFL" : act.sa_handler == SIG_IGN ? "SIG_IGN" : "a function",
               (unsigned)act.sa_flags);
        n++;
    }
    printf("  inherited: %d signal(s) of 1..31 not at (SIG_DFL, no flags)\n", n);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        say(argv[1]);
        return 0;
    }
    say("as this program was started");
    say_all();
    for (int restart = 0; restart < 2; restart++) {
        pid_t pid = fork();
        if (pid == 0) {
            struct sigaction act;
            memset(&act, 0, sizeof act);
            act.sa_handler = taken;
            act.sa_flags = restart ? SA_RESTART : 0;
            sigaction(SIGUSR2, &act, NULL);
            execl(argv[0], argv[0],
                  restart ? "after an exec from a parent whose handler had SA_RESTART"
                          : "after an exec from a parent whose handler had no SA_RESTART", (char *)NULL);
            _exit(127);
        }
        waitpid(pid, NULL, 0);
    }
    /* signal() itself, then back to the default, in one process. */
    signal(SIGUSR2, taken);
    signal(SIGUSR2, SIG_DFL);
    say("after signal(handler) then signal(SIG_DFL) in this process");
    return 0;
}
