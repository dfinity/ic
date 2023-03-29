#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <systemd/sd-journal.h>
#include <termios.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "network_info.h"

namespace {

void
check_panic_errno(int return_code, const std::string& tty_dev, const char* info)
{
    if (return_code >= 0) {
        return;
    }

    std::string message = "infogetty(" + tty_dev + ") " + info + ": " + strerror(errno);
    sd_journal_print(LOG_ERR, "%s", message.c_str());
    _exit(1);
}

}

void
open_tty(const std::string& tty_dev, struct termios* term)
{
    struct group* grp = getgrnam("tty");
    pid_t pid = ::getpid();
    gid_t gid = grp ? grp->gr_gid : 0;

    // Open to gain terminal control and deliver hangup on terminal.

    int fd = ::open(tty_dev.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
    check_panic_errno(fd, tty_dev, "initial open failed");

    check_panic_errno(::fchown(fd, 0, gid), tty_dev, "fchown failed");
    check_panic_errno(::fchmod(fd, (gid ? 0620 : 0600)), tty_dev, "fchmod failed");

    pid_t tid = ::tcgetsid(fd);
    if (tid < 0 || pid != tid) {
        check_panic_errno(::ioctl(fd, TIOCSCTTY, 1), tty_dev, "initial TIOCSCTTY failed");
    }

    // No open descriptors may remain before terminal hangup.
    ::close(0);
    ::close(1);
    ::close(2);
    ::close(fd);

    check_panic_errno(vhangup(), tty_dev, "vhangup failed");

    // Open again, this time for real.
    fd = ::open(tty_dev.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
    check_panic_errno(fd, tty_dev, "terminal open failed");

    tid = ::tcgetsid(fd);
    if (tid < 0 || pid != tid) {
        check_panic_errno(::ioctl(fd, TIOCSCTTY, 1), tty_dev, "terminal TIOCSCTTY failed");
    }

    ::tcsetpgrp(0, pid);

    if (::dup(0) != 1) {
        check_panic_errno(-1, tty_dev, "dup to stdout failed");
    }
    if (::dup(0) != 2) {
        check_panic_errno(-1, tty_dev, "dup to stderr failed");
    }

    std::memset(term, 0, sizeof(*term));
    check_panic_errno(::tcgetattr(0, term), tty_dev, "tcgetattr failed");

    ::setenv("TERM", "linux", 1);
}

void
loop_print_sysinfo(const std::string& tty_dev, bool allow_root_login, const struct termios& saved_tios)
{
    struct termios cbreak_tios = saved_tios;
    cbreak_tios.c_lflag = cbreak_tios.c_lflag & ~ (ICANON | ECHO);
    cbreak_tios.c_cc[VMIN] = 1;
    cbreak_tios.c_cc[VTIME] = 0;
    check_panic_errno(::tcsetattr(0, TCSANOW, &cbreak_tios), tty_dev, "tcsetattr(cbreak) failed");

    for (;;) {
        auto info = format_network_info(read_network_info());
        if (allow_root_login) {
            info += "Press ENTER to activate console\n";
        }
        info += "\n";
        check_panic_errno(write(1, info.data(), info.size()), tty_dev, "write(info) failed");

        struct pollfd pfds[1];
        pfds[0].fd = 0;
        pfds[0].events = POLLIN;
        int res = ::poll(pfds, 1, 30000);
        check_panic_errno(res, tty_dev, "poll tty failed");

        if (res > 0 && (pfds[0].revents != 0)) {
            // Drain characters available through poll. (If we exit the loop
            // it is sort of redundant with the TCSAFLUSH below, but we want
            // to make sure that the buffer is emptied otherwise).
            char buffer[1024];
            if (::read(0, buffer, 1024) < 0 && errno != EAGAIN) {
                check_panic_errno(-1, tty_dev, "read to drain terminal failed");
            }
            if (allow_root_login) {
                break;
            }
        }
    }


    // Turn off non-blocking mode (might confuse shell).
    fcntl(0, F_SETFL, fcntl(0, F_GETFL, 0) & ~O_NONBLOCK);

    check_panic_errno(::tcsetattr(0, TCSAFLUSH, &saved_tios), tty_dev, "tcsetattr(restore) failed");
}

struct options {
    std::string tty_dev;
    bool allow_root_login = false;
};

options
parse_commandline_options(int argc, char** argv)
{
    options opts;

    for (int n = 1; n < argc; ++n) {
        auto arg = std::string_view(argv[n]);

        // -r points to a (potential) file. If it exists,
        // allow root login on console.
        if (arg == "-r") {
            ++n;
            if (n >= argc) {
                sd_journal_print(LOG_ERR, "missing argument to -r switch");
                _exit(1);
            }

            struct stat st;
            int res = ::stat(argv[n], &st);
            if (res == 0) {
                // File exists, allow root login.
                opts.allow_root_login = true;
            }
        } else {
            opts.tty_dev = arg;
        }
    }

    return opts;
}

int
main(int argc, char** argv)
{
    auto opts = parse_commandline_options(argc, argv);

    // Ignore critical signals while we are setting up terminal and while
    // we are still in "info" mode. Save old signal disposition to restore
    // later.
    struct sigaction sa;
    struct sigaction saved_hup;
    struct sigaction saved_quit;
    struct sigaction saved_int;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;
    sigemptyset (&sa.sa_mask);
    sigaction(SIGHUP, &sa, &saved_hup);
    sigaction(SIGQUIT, &sa, &saved_quit);
    sigaction(SIGINT, &sa, &saved_int);

    struct termios tios;

    // Assume terminal control.
    open_tty(opts.tty_dev, &tios);

    // System info loop, until user requests to activate terminal.
    loop_print_sysinfo(opts.tty_dev, opts.allow_root_login, tios);


    // Restore signal dispositions before executing shell.
    sigaction(SIGHUP, &saved_hup, NULL);
    sigaction(SIGQUIT, &saved_quit, NULL);
    sigaction(SIGINT, &saved_int, NULL);

    // Drop into shell. We do this via the "login" binary which establishes
    // everything nicely to have a login session.
    // When the shell terminates, systemd will respawn us and we will take
    // over the terminal again.
    const char* cmdline[] = {
        "/usr/bin/login",
        "-f",
        "-p",
        "root",
        0
    };
    check_panic_errno(::execve(cmdline[0], const_cast<char**>(cmdline), environ), opts.tty_dev, "execve login failed");

    return 1;
}
