#define UNW_LOCAL_ONLY
#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

#include <libunwind.h>

// Helpers to format string in pre-allocated buffer. All helpers take
// current position and "limit" up to which they can fill buffer. They
// return new position.
// This is open-coded because we will have to do without memory allocations.

static char*
push_char(char c, char* pos, char* limit)
{
    if (pos != limit) {
        *pos++ = c;
    }
    return pos;
}

static char*
push_string(const char* s, char* pos, char* limit)
{
    if (!s) {
        s = "(null)";
    }
    while (*s) {
        pos = push_char(*s, pos, limit);
        ++s;
    }
    return pos;
}

static const char HEXDIGITS[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

static char*
push_hex(uintptr_t addr, char* pos, char* limit)
{
    const size_t NUM_DIGITS = sizeof(uintptr_t) * 2;
    for (size_t n = 0; n < NUM_DIGITS; ++n) {
        int digit = (addr >> ((NUM_DIGITS - n - 1) * 4)) & 0xf;
        pos = push_char(HEXDIGITS[digit], pos, limit);
    }
    return pos;
}

static char*
push_decimal(int value, char* pos, char* limit)
{
    if (value < 0) {
        pos = push_char('-', pos, limit);
    }
    unsigned int uvalue = value < 0 ? (~((unsigned int)value)) + 1 : ((unsigned int)value);
    static const unsigned int divider_steps[] = {
        1000000000,
        100000000,
        10000000,
        1000000,
        100000,
        10000,
        1000,
        100,
        10,
        1
    };
    unsigned int divider = 1;
    for (size_t n = 0; n < sizeof(divider_steps) / sizeof(divider_steps[0]); ++n) {
        if (uvalue >= divider_steps[n]) {
            divider = divider_steps[n];
            break;
        }
    }

    while (divider) {
        unsigned int digit = (uvalue / divider) % 10;
        pos = push_char('0' + digit, pos, limit);
        divider = divider / 10;
    }

    return pos;
}

static char*
push_reg(const mcontext_t* mctx, int regindex, const char* regname, char* pos, char* limit)
{
    pos = push_string(regname, pos, limit);
    pos = push_string("=0x", pos, limit);
    pos = push_hex(mctx->gregs[regindex], pos, limit);
    pos = push_char(' ', pos, limit);
    return pos;
}

static char*
dump_memory(uintptr_t around, char* pos, char* limit)
{
    static const size_t NUM_BYTES = 24;
    uintptr_t low = around > 4 ? (around - 4) & ~7 : 0;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) {
        return push_string("(cannot open pipe)", pos, limit);
    }

    // This will try to read from memory, but return with EFAULT rather
    // than sigsegv. If it returns we know that it is safe to read this
    // memory.
    ssize_t write_result = write(fds[1], (void*)low, NUM_BYTES);
    close(fds[0]);
    close(fds[1]);

    if ((size_t)write_result != NUM_BYTES) {
        return push_string(" not readable", pos, limit);
    }

    pos = push_char(low == around ? '[' : ' ', pos, limit);
    for (size_t n = 0; n < NUM_BYTES; ++n) {
        uintptr_t addr = low + n;
        uint8_t value = *(uint8_t*)addr;
        pos = push_char(HEXDIGITS[(value >> 4) & 0xf], pos, limit);
        pos = push_char(HEXDIGITS[(value >> 0) & 0xf], pos, limit);
        if (addr == around) {
            pos = push_char(']', pos, limit);
        } else if (addr + 1 == around) {
            pos = push_char('[', pos, limit);
        } else {
            pos = push_char(' ', pos, limit);
        }
    }

    return pos;
}

extern const char* const sys_siglist[];

void handler(int signo, siginfo_t* info, void* detail)
{
    // Async-signal safety: This handler is safe _except_ for the fact that it
    // does not preserve errno. (So, strictly speaking, it would be unsafe).
    // However, it is not necessary to preserve errno because we will terminate
    // the process at the end anyways.

    // To format backtrace, need some temporary formatting buffers -- must
    // be allocated on stack (no memory alloc allowed!).
    char resolved_symbol[256];
    char buffer[256];
    // Limit of buffer, reserve byte for \n at the end. We want each written
    // message terminated by \n to ensure logger can process correctly.
    char* limit = buffer + sizeof(buffer) - 1;

    // All writes are done directly using syscall to write to file descriptor
    // number 2, bypassing all standard library. This is necessary to ensure
    // there are no memory allocations. This fd is stderr and is wired up to go
    // straight into the logs.

    // Dump signal info.
    {
        char* pos = buffer;
        pos = push_string("Terminating on signal ", pos, limit);
        pos = push_decimal(signo, pos, limit);
        pos = push_string(" (", pos, limit);
        pos = push_string(sys_siglist[signo], pos, limit);
        pos = push_string(") at 0x", pos, limit);
        pos = push_hex((uintptr_t)info->si_addr, pos, limit);
        *pos++ = '\n';
        // Ignore write errors as there is not much we can do...
        (void)write(2, buffer, pos - buffer);
    }

    // Dump registers
    struct ucontext_t* uctx = (struct ucontext_t*)detail;
    {
        char* pos = buffer;
        pos = push_reg(&uctx->uc_mcontext, REG_RIP, "rip", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_EFL, "efl", pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    {
        char* pos = buffer;
        pos = push_reg(&uctx->uc_mcontext, REG_RAX, "rax", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RBX, "rbx", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RCX, "rcx", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RDX, "rdx", pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    {
        char* pos = buffer;
        pos = push_reg(&uctx->uc_mcontext, REG_RSP, "rsp", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RBP, "rbp", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RSI, "rsi", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_RDX, "rdi", pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    {
        char* pos = buffer;
        pos = push_reg(&uctx->uc_mcontext, REG_R8, "r8 ", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R9, "r9 ", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R10, "r10", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R11, "r11", pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    {
        char* pos = buffer;
        pos = push_reg(&uctx->uc_mcontext, REG_R12, "r12", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R13, "r13", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R14, "r14", pos, limit);
        pos = push_reg(&uctx->uc_mcontext, REG_R15, "r15", pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }

    // Dump memory around rip / rsp
    {
        char* pos = buffer;
        pos = push_string("mem@rip:", pos, limit);
        pos = dump_memory(uctx->uc_mcontext.gregs[REG_RIP], pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    {
        char* pos = buffer;
        pos = push_string("mem@rsp:", pos, limit);
        pos = dump_memory(uctx->uc_mcontext.gregs[REG_RSP], pos, limit);
        *pos++ = '\n';
        (void)write(2, buffer, pos - buffer);
    }
    // Collect and format stack trace. We may not be able to resolve
    // symbols, but addresses may help already.
    (void)write(2, "Backtrace:\n", 11);
    unw_cursor_t cursor;
    unw_context_t context;
    unw_getcontext(&context);
    unw_init_local(&cursor, &context);
    int depth = 0;
    while (unw_step(&cursor) != 0) {
        unw_word_t ip, sp, off;

        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);

        const char* name = "(unknown)";
        if (unw_get_proc_name(&cursor, resolved_symbol, sizeof(resolved_symbol) - 1, &off) == 0) {
            name = resolved_symbol;
            // According to experiments, callee refuses to put in any symbol
            // if the buffer is too small to fit both the name and terminating
            // zero.
            // Nevertheless, forcibly zero terminate string, it does not hurt.
            resolved_symbol[sizeof(resolved_symbol) - 1] = 0;
        }

        char* pos = buffer;
        pos = push_decimal(++depth, pos, limit);
        pos = push_string(" ip=0x", pos, limit);
        pos = push_hex(ip, pos, limit);
        pos = push_string(" sp=0x", pos, limit);
        pos = push_hex(sp, pos, limit);
        pos = push_char(' ', pos, limit);
        pos = push_string(name, pos, limit);
        pos = push_string(" + 0x", pos, limit);
        pos = push_hex(off, pos, limit);
        *pos++ = '\n';
        // Write directly via syscall to stderr.
        (void)write(2, buffer, pos - buffer);
    }

    // Forcibly restore the default handler for this signal: The default
    // handler will terminate the process.
    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signo, &sa, 0);

    // Falling through will resume executing faulting instruction, and will
    // therefore simply fault again. This time with old signal handler, so
    // process will terminate.
}

void install_backtrace_handler()
{
    struct sigaction sa;
    sa.sa_sigaction = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
}
