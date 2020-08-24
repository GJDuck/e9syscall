/*
 * Copyright (C) 2020 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>

#include "e9syscall.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>

#define COLOR_CLEAR     0
#define COLOR_RED       1
#define COLOR_GREEN     2
#define COLOR_YELLOW    3

#define ARG_NONE        0
#define ARG_INTEGER     1
#define ARG_POINTER     2
#define ARG_STRING      3
#define ARG_BUFFER      4
#define ARG_OPEN_FLAGS  5
#define ARG_OPEN_MODE   6
#define ARG_PROT        7
#define ARG_MMAP_FLAGS  8
#define ARG_SIGNAL      9

struct arg_s
{
    uint8_t kind;
    const char name[11];
    const char type[28];
};

struct syscall_s
{
    const char name[16];
    struct arg_s args[6];  
};

#define ARG(kind, type, name)   {ARG_ ## kind, (name), (type)}
#define END                     {0}

static const struct syscall_s syscalls[] =
{
    {"read",
        {ARG(INTEGER, "int", "fd"),
         ARG(POINTER, "char *", "buf"),
         ARG(INTEGER, "size_t", "count"),
         END}},
    {"write",
        {ARG(INTEGER, "int", "fd"),
         ARG(BUFFER,  "const char *", "buf"),
         ARG(INTEGER, "size_t", "count"),
         END}},
    {"open",
        {ARG(STRING,     "const char *", "pathname"),
         ARG(OPEN_FLAGS, "int", "flags"),
         ARG(OPEN_MODE,  "int", "mode"),
         END}},
    {"close",
        {ARG(INTEGER, "int", "fd"),
         END}},
    {"stat",
        {ARG(STRING,  "const char *", "pathname"),
         ARG(POINTER, "struct stat *", "buf"),
         END}},
    {"fstat",
        {ARG(INTEGER, "int", "fd"),
         ARG(POINTER, "struct stat *", "buf"),
         END}},
    {"lstat",
        {ARG(STRING,  "const char *", "pathname"),
         ARG(POINTER, "struct stat *", "buf"),
         END}},
    {"poll",
        {ARG(POINTER, "struct pollfd *", "fds"),
         ARG(INTEGER, "nfds_t", "nfds"),
         ARG(INTEGER, "int", "timeout"),
         END}},
    {"lseek",
        {ARG(INTEGER, "fd", "int"),
         ARG(INTEGER, "offset", "off_t"),
         ARG(INTEGER, "whence", "int"),
         END}},
    {"mmap",
        {ARG(POINTER, "void *", "addr"),
         ARG(INTEGER, "size_t", "length"),
         ARG(PROT,    "int", "prot"),
         ARG(INTEGER, "int", "flags"),
         ARG(INTEGER, "int", "fd"),
         ARG(INTEGER, "off_t", "offset")}},
    {"mprotect",
        {ARG(POINTER, "void *", "addr"),
         ARG(INTEGER, "size_t", "length"),
         ARG(PROT,    "int", "prot"),
         END}},
    {"munmap",
        {ARG(POINTER, "void *", "addr"),
         ARG(INTEGER, "size_t", "length"),
         END}},
    {"brk",
        {ARG(POINTER, "void *", "addr"),
         END}},
    {"rt_sigaction",
        {ARG(SIGNAL, "int", "signum"),
         ARG(POINTER, "const struct sigaction *", "act"),
         ARG(POINTER, "struct sigaction *", "oldact"),
         END}},
    {"rt_sigprocmask",
        {ARG(INTEGER, "int", "how"),
         ARG(POINTER, "const sigset_t *", "set"),
         ARG(POINTER, "signet_t *", "oldset"),
         ARG(INTEGER, "size_t", "sigsetsize"),
         END}},
    {"rt_sigreturn",
        {END}},
    {"ioctl",
        {ARG(INTEGER, "int", "fd"),
         ARG(INTEGER, "unsigned long", "request"),
         ARG(POINTER, "void *", "argp"),
         END}},
    // Add more if you like...
};

/**************************************************************************/

struct stream_s
{
    size_t pos;
    char buf[4096];
};

static void write_char(struct stream_s *stream, char c)
{
    if (stream->pos >= sizeof(stream->buf))
        return;
    stream->buf[stream->pos++] = c;
}

static void write_string(struct stream_s *stream, const char *s)
{
    for (; *s != '\0'; s++)
        write_char(stream, *s);
}

static void write_string_2(struct stream_s *stream, const char *s,
    const char *t)
{
    write_string(stream, s);
    write_string(stream, t);
}

static void write_color(struct stream_s *stream, int color)
{
    if (stream->pos >= sizeof(stream->buf) - 6)
        return;
    switch (color)
    {
        case COLOR_CLEAR:
            write_string(stream, "\33[0m");
            break;
        case COLOR_RED:
            write_string(stream, "\33[31m");
            break;
        case COLOR_GREEN:
            write_string(stream, "\33[32m");
            break;
        case COLOR_YELLOW:
            write_string(stream, "\33[33m");
            break;
    }
}

static void write_int(struct stream_s *stream, intptr_t x)
{
    if (x < 0)
    {
        write_char(stream, '-');
        x = -x;
    }
    if (x == 0)
    {
        write_char(stream, '0');
        return;
    }
    uintptr_t y = (uintptr_t)x;
    uintptr_t r = 10000000000000000000ull;
    bool seen = false;
    while (r != 0)
    {
        char c = '0' + y / r;
        y %= r;
        r /= 10;
        if (!seen && c == '0')
            continue;
        seen = true;
        write_char(stream, c);
    }
}

static const char xdigs[] = "0123456789abcdef";
static void write_hex(struct stream_s *stream, uintptr_t x)
{
    write_string(stream, "0x");
    if (x == 0)
    {
        write_char(stream, '0');
        return;
    }
    int shift = (15 * 4);
    bool seen = false;
    while (shift >= 0)
    {
        char c = xdigs[(x >> shift) & 0xF];
        shift -= 4;
        if (!seen && c == '0')
            continue;
        seen = true;
        write_char(stream, c);
    }
}

static void write_byte(struct stream_s *stream, uint8_t c)
{
    switch (c)
    {
        case '\0':
            write_string(stream, "\\0");
            return;
        case '\t':
            write_string(stream, "\\t");
            return;
        case '\n':
            write_string(stream, "\\n");
            return;
        case '\r':
            write_string(stream, "\\r");
            return;
        case '\v':
            write_string(stream, "\\v");
            return;
        default:
            break;
    }
    if (c < ' ' || c >= 127)
    {
        write_string(stream, "\\x0");
        write_char(stream, xdigs[(c >> 4) & 0xF]);
        write_char(stream, xdigs[c & 0xF]);
        return;
    }
    write_char(stream, (char)c);
}

static void write_open_flags(struct stream_s *stream, intptr_t flags)
{
    if ((flags & O_RDWR) == O_RDWR)
        write_string(stream, "O_RDWR");
    else if ((flags & O_RDONLY) == O_RDONLY)
        write_string(stream, "O_RDONLY");
    else if ((flags & O_WRONLY) == O_WRONLY)
        write_string(stream, "O_WRONLY");
    else
        write_string(stream, "???");
    if (flags & O_APPEND)
        write_string(stream, " | O_APPEND");
    if (flags & O_ASYNC)
        write_string(stream, " | O_ASYNC");
    if (flags & O_CLOEXEC)
        write_string(stream, " | O_CLOEXEC");
    if (flags & O_CREAT)
        write_string(stream, " | O_CREAT");
    if (flags & O_DIRECTORY)
        write_string(stream, " | O_DIRECTORY");
    if (flags & O_DSYNC)
        write_string(stream, " | O_DSYNC");
    if (flags & O_EXCL)
        write_string(stream, " | O_EXCL");
    if (flags & O_NOCTTY)
        write_string(stream, " | O_NOCTTY");
    if (flags & O_NOFOLLOW)
        write_string(stream, " | O_NOFOLLOW");
    if (flags & O_NONBLOCK)
        write_string(stream, " | O_NONBLOCK");
    if (flags & O_SYNC)
        write_string(stream, " | O_SYNC");
    if (flags & O_TRUNC)
        write_string(stream, " | O_TRUNC");
    flags &= ~(O_ACCMODE | O_APPEND | O_CLOEXEC | O_CREAT | O_DIRECTORY |
        O_DSYNC | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_SYNC |
        O_TRUNC);
    if (flags != 0)
    {
        write_string(stream, " | ");
        write_hex(stream, flags);
    }
}

static void write_mode(struct stream_s *stream, intptr_t mode)
{
    size_t pos = stream->pos;
    if ((mode & S_IRWXU) == S_IRWXU)
        write_string(stream, "S_IRWXU");
    else
    {
        if (mode & S_IRUSR)
            write_string(stream, "S_IRUSR");
        if (mode & S_IWUSR)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IWUSR");
        if (mode & S_IXUSR)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IXUSR");
    }
    if ((mode & S_IRWXG) == S_IRWXG)
        write_string_2(stream, (stream->pos == pos? "": " | "), "S_IRWXG");
    else
    {
        if (mode & S_IRGRP)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IRGRP");
        if (mode & S_IWGRP)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IWGRP");
        if (mode & S_IXGRP)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IXGRP");
    }
    if ((mode & S_IRWXO) == S_IRWXO)
        write_string_2(stream, (stream->pos == pos? "": " | "), "S_IRWXG");
    else
    {
        if (mode & S_IROTH)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IROTH");
        if (mode & S_IWOTH)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IWOTH");
        if (mode & S_IXOTH)
            write_string_2(stream, (stream->pos == pos? "": " | "), "S_IXOTH");
    }
    if (mode & S_ISUID)
        write_string_2(stream, (stream->pos == pos? "": " | "), "S_ISUID");
    if (mode & S_ISGID)
        write_string_2(stream, (stream->pos == pos? "": " | "), "S_ISGID");
    if (mode & S_ISVTX)
        write_string_2(stream, (stream->pos == pos? "": " | "), "S_ISVTX");
    intptr_t mode0 = mode;
    mode &= ~(S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX);
    if (mode != 0 || mode0 == 0)
    {
        write_string(stream, (stream->pos == pos? "": " | "));
        write_hex(stream, mode);
    }
}

static void write_prot(struct stream_s *stream, intptr_t prot)
{
    if (prot == PROT_NONE)
    {
        write_string(stream, "PROT_NONE");
        return;
    }
    size_t pos = stream->pos;
    if (prot & PROT_READ)
        write_string(stream, "PROT_READ");
    if (prot & PROT_WRITE)
        write_string_2(stream, (stream->pos == pos? "": " | "), "PROT_WRITE");
    if (prot & PROT_EXEC)
        write_string_2(stream, (stream->pos == pos? "": " | "), "PROT_EXEC");
    prot &= ~(PROT_READ | PROT_WRITE | PROT_EXEC);
    if (prot != 0)
    {
        write_string(stream, (stream->pos == pos? "": " | "));
        write_hex(stream, prot);
    }
}

static void write_signal(struct stream_s *stream, intptr_t sig)
{
    switch (sig)
    {
        case SIGHUP:
            write_string(stream, "SIGHUP");
            break;
        case SIGINT:
            write_string(stream, "SIGINT");
            break;
        case SIGQUIT:
            write_string(stream, "SIGQUIT");
            break;
        case SIGFPE:
            write_string(stream, "SIGFPE");
            break;
        case SIGKILL:
            write_string(stream, "SIGKILL");
            break;
        case SIGSEGV:
            write_string(stream, "SIGSEGV");
            break;
        case SIGPIPE:
            write_string(stream, "SIGPIPE");
            break;
        case SIGALRM:
            write_string(stream, "SIGALRM");
            break;
        case SIGTERM:
            write_string(stream, "SIGTERM");
            break;
        case SIGUSR1:
            write_string(stream, "SIGUSR1");
            break;
        case SIGUSR2:
            write_string(stream, "SIGUSR2");
            break;
        case SIGCHLD:
            write_string(stream, "SIGCHLD");
            break;
        case SIGCONT:
            write_string(stream, "SIGCONT");
            break;
        case SIGSTOP:
            write_string(stream, "SIGSTOP");
            break;
        case SIGBUS:
            write_string(stream, "SIGBUS");
            break;
        case SIGPOLL:
            write_string(stream, "SIGPOLL");
            break;
        case SIGPROF:
            write_string(stream, "SIGPROF");
            break;
        case SIGSYS:
            write_string(stream, "SIGSYS");
            break;
        case SIGTRAP:
            write_string(stream, "SIGTRAP");
            break;
        default:
            write_int(stream, sig);
            break;
    }
}

/*
 * PRINT: Print syscall information to stderr.
 */
int hook(int callno, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t *result)
{
    struct stream_s stream0;
    struct stream_s *stream = &stream0;
    stream->pos = 0;

    intptr_t args[] = {arg1, arg2, arg3, arg4, arg5, arg6, 0};
    if (callno >= 0 && callno < sizeof(syscalls) / sizeof(syscalls[0]))
    {
        const struct syscall_s *info = syscalls + callno;

        write_color(stream, COLOR_YELLOW);
        write_string(stream, info->name);
        write_color(stream, COLOR_CLEAR);
        write_char(stream, '(');

        bool first = true;
        for (unsigned i = 0; i < 6; i++)
        {
            if (info->args[i].kind == ARG_NONE)
                break;
            if (!first)
                write_string(stream, ", ");
            first = false;
            write_string(stream, info->args[i].name);
            write_string(stream, "=(");
            write_color(stream, COLOR_GREEN);
            write_string(stream, info->args[i].type);
            write_color(stream, COLOR_CLEAR);
            write_char(stream, ')');
            write_color(stream, COLOR_RED);
            switch (info->args[i].kind)
            {
                case ARG_POINTER:
                    write_hex(stream, args[i]);
                    break;
                case ARG_INTEGER:
                    write_int(stream, args[i]);
                    break;
                case ARG_STRING:
                    write_char(stream, '\"');
                    write_string(stream, (const char *)args[i]);
                    write_char(stream, '\"');
                    break;
                case ARG_BUFFER:
                {
                    size_t len = (size_t)args[i+1];
                    const uint8_t *buf = (const uint8_t *)args[i];
                    write_char(stream, '\"');
                    for (size_t j = 0; j < len; j++)
                        write_byte(stream, buf[j]);
                    write_char(stream, '\"');
                    break;
                }
                case ARG_OPEN_FLAGS:
                    write_open_flags(stream, args[i]);
                    break;
                case ARG_OPEN_MODE:
                {
                    intptr_t flags = (i == 0? 0x0: args[i-1]);
                    intptr_t mode = args[i];
                    if ((flags & O_CREAT) == 0)
                        write_hex(stream, mode);
                    else
                        write_mode(stream, mode);
                    break;
                }
                case ARG_PROT:
                    write_prot(stream, args[i]);
                    break;
                case ARG_SIGNAL:
                    write_signal(stream, args[i]);
                    break;
                default:
                    write_string(stream, "???");
                    break;
            }
            write_color(stream, COLOR_CLEAR);
        }

        write_string(stream, ")\n");
    }
    else
    {
        write_string(stream, "syscall(callno=");
        write_int(stream, callno);
        for (unsigned i = 0; i < 6; i++)
        {
            write_string(stream, ", arg");
            write_int(stream, (intptr_t)i);
            write_char(stream, '=');
            write_hex(stream, args[i]);
        }
        write_string(stream, ")\n");
    }

    syscall(SYS_write, STDERR_FILENO, stream->buf, stream->pos);

    return -1;
}

