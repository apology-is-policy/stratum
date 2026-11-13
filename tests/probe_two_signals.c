/* Two signals taken where a write comes back: whose action says whether the write is made again?
 *
 * A process in a background group writes one byte to its terminal under tostop, N times. SIGTTOU
 * has a handler that does not restart (and does not stop); SIGINT has one that restarts. Its
 * parent, the session's leader, sends it SIGINT without pause. Each write must fail with EINTR
 * after ONE SIGTTOU; a write the kernel made again by itself took a second SIGTTOU before it
 * failed, so (SIGTTOU handled) - N counts the writes made again. Run twice: as it is, and with
 * every signal but SIGTTOU blocked for the length of the write.
 *
 *   cc -O2 -o two-signals two-signals.c && ./two-signals [N]
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static volatile long ttou, ints;
static void on_ttou(int s) { (void)s; ttou++; }
static void on_int(int s) { (void)s; ints++; }

/* Before the first SIGINT can come: its default action would end the writer. */
static void arm(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    sigemptyset(&a.sa_mask);
    a.sa_handler = on_ttou;
    a.sa_flags = 0;
    sigaction(SIGTTOU, &a, NULL);
    a.sa_handler = on_int;
    a.sa_flags = SA_RESTART;
    sigaction(SIGINT, &a, NULL);
}

static void writer(int tty, int out, long n, int others_wait)
{
    sigset_t others, prev;
    sigfillset(&others);
    sigdelset(&others, SIGTTOU);
    long wrote = 0, eintr = 0, other = 0;
    for (long i = 0; i < n; i++) {
        if (others_wait) sigprocmask(SIG_BLOCK, &others, &prev);
        ssize_t r = write(tty, "x", 1);
        int e = errno;
        if (others_wait) sigprocmask(SIG_SETMASK, &prev, NULL);
        if (r == 1) wrote++; else if (e == EINTR) eintr++; else other++;
    }
    char line[256];
    int len = snprintf(line, sizeof line, "%ld %ld %ld %ld %ld %ld\n", n, wrote, eintr, other, (long)ttou, (long)ints);
    if (write(out, line, (size_t)len) != len) _exit(3);
    _exit(0);
}

static int once(long n, int others_wait, const char *sys)
{
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { perror("pty"); return 2; }
    const char *name = ptsname(m);
    int res[2];
    if (pipe(res) != 0) { perror("pipe"); return 2; }
    pid_t leader = fork();
    if (leader == 0) {
        close(m); close(res[0]);
        setsid();
        int tty = open(name, O_RDWR);
        if (tty < 0) _exit(4);
        (void)ioctl(tty, TIOCSCTTY, 0);
        struct termios t;
        if (tcgetattr(tty, &t) != 0) _exit(5);
        t.c_lflag |= TOSTOP;
        if (tcsetattr(tty, TCSANOW, &t) != 0) _exit(6);
        if (tcsetpgrp(tty, getpgrp()) != 0) _exit(7);
        int armed[2];
        if (pipe(armed) != 0) _exit(8);
        pid_t w = fork();
        if (w == 0) {
            close(armed[0]);
            setpgid(0, 0);
            arm();
            if (write(armed[1], "a", 1) != 1) _exit(9);
            close(armed[1]);
            writer(tty, res[1], n, others_wait);
        }
        setpgid(w, w);
        close(armed[1]);
        char c;
        if (read(armed[0], &c, 1) != 1) _exit(10);
        int st = 0;
        while (waitpid(w, &st, WNOHANG) == 0) kill(w, SIGINT);
        if (!WIFEXITED(st)) {
            char why[64];
            int len = snprintf(why, sizeof why, "the writer ended by signal %d\n", WIFSIGNALED(st) ? WTERMSIG(st) : -1);
            (void)!write(res[1], why, (size_t)len);
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 11);
    }
    close(res[1]);
    fcntl(m, F_SETFL, O_NONBLOCK);
    char buf[4096], line[256];
    size_t got = 0;
    for (;;) {
        (void)!read(m, buf, sizeof buf);
        ssize_t r = read(res[0], line + got, sizeof line - 1 - got);
        if (r > 0) { got += (size_t)r; if (memchr(line, '\n', got)) break; }
        else if (r == 0) break;
        else if (errno != EINTR) break;
    }
    line[got] = 0;
    int st = 0;
    waitpid(leader, &st, 0);
    long N, wrote, eintr, other, t, i;
    if (sscanf(line, "%ld %ld %ld %ld %ld %ld", &N, &wrote, &eintr, &other, &t, &i) != 6) {
        printf("%s, %s: no result (the leader ended %d): %s\n", sys, others_wait ? "the others blocked" : "as it is",
               WIFEXITED(st) ? WEXITSTATUS(st) : -1, line);
        return 1;
    }
    printf("%s, %s: %ld writes from behind under tostop: %ld failed with EINTR, %ld wrote, %ld failed otherwise; "
           "SIGTTOU handled %ld times, SIGINT (restarting) %ld times: %ld writes were made again by the kernel\n",
           sys, others_wait ? "every other signal blocked for the write" : "as it is", N, eintr, wrote, other, t, i, t - eintr);
    close(m); close(res[0]);
    return 0;
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 20000;
    struct utsname u;
    uname(&u);
    int a = once(n, 0, u.sysname);
    int b = once(n, 1, u.sysname);
    return a | b;
}
