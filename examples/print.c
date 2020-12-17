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

static void write_color(FILE *stream, int color)
{
    switch (color)
    {
        case COLOR_CLEAR:
            fputs("\33[0m", stream);
            break;
        case COLOR_RED:
            fputs("\33[31m", stream);
            break;
        case COLOR_GREEN:
            fputs("\33[32m", stream);
            break;
        case COLOR_YELLOW:
            fputs("\33[33m", stream);
            break;
    }
}

static void write_byte(FILE *stream, uint8_t c)
{
    switch (c)
    {
        case '\0':
            fputs("\\0", stream);
            return;
        case '\t':
            fputs("\\t", stream);
            return;
        case '\n':
            fputs("\\n", stream);
            return;
        case '\r':
            fputs("\\r", stream);
            return;
        case '\v':
            fputs("\\v", stream);
            return;
        default:
            break;
    }
    if (c < ' ' || c >= 127)
    {
        fprintf(stream, "\\x0%.2x", (unsigned)c);
        return;
    }
    fputc((char)c, stream);
}

static void write_open_flags(FILE *stream, intptr_t flags)
{
    if ((flags & O_RDWR) == O_RDWR)
        fputs("O_RDWR", stream);
    else if ((flags & O_RDONLY) == O_RDONLY)
        fputs("O_RDONLY", stream);
    else if ((flags & O_WRONLY) == O_WRONLY)
        fputs("O_WRONLY", stream);
    else
        fputs("???", stream);
    if (flags & O_APPEND)
        fputs(" | O_APPEND", stream);
    if (flags & O_ASYNC)
        fputs(" | O_ASYNC", stream);
    if (flags & O_CLOEXEC)
        fputs(" | O_CLOEXEC", stream);
    if (flags & O_CREAT)
        fputs(" | O_CREAT", stream);
    if (flags & O_DIRECTORY)
        fputs(" | O_DIRECTORY", stream);
    if (flags & O_DSYNC)
        fputs(" | O_DSYNC", stream);
    if (flags & O_EXCL)
        fputs(" | O_EXCL", stream);
    if (flags & O_NOCTTY)
        fputs(" | O_NOCTTY", stream);
    if (flags & O_NOFOLLOW)
        fputs(" | O_NOFOLLOW", stream);
    if (flags & O_NONBLOCK)
        fputs(" | O_NONBLOCK", stream);
    if (flags & O_SYNC)
        fputs(" | O_SYNC", stream);
    if (flags & O_TRUNC)
        fputs(" | O_TRUNC", stream);
    flags &= ~(O_ACCMODE | O_APPEND | O_CLOEXEC | O_CREAT | O_DIRECTORY |
        O_DSYNC | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_SYNC |
        O_TRUNC);
    if (flags != 0)
        fprintf(stream, " | 0x%x", flags);
}

static void write_mode(FILE *stream, intptr_t mode)
{
    size_t pos = 0;
    if ((mode & S_IRWXU) == S_IRWXU)
        pos += fputs("S_IRWXU", stream);
    else
    {
        if (mode & S_IRUSR)
            pos += fputs("S_IRUSR", stream);
        if (mode & S_IWUSR)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IWUSR");
        if (mode & S_IXUSR)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IXUSR");
    }
    if ((mode & S_IRWXG) == S_IRWXG)
        fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IRWXG");
    else
    {
        if (mode & S_IRGRP)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IRGRP");
        if (mode & S_IWGRP)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IWGRP");
        if (mode & S_IXGRP)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IXGRP");
    }
    if ((mode & S_IRWXO) == S_IRWXO)
        fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IRWXG");
    else
    {
        if (mode & S_IROTH)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IROTH");
        if (mode & S_IWOTH)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IWOTH");
        if (mode & S_IXOTH)
            pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_IXOTH");
    }
    if (mode & S_ISUID)
        pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_ISUID");
    if (mode & S_ISGID)
        pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_ISGID");
    if (mode & S_ISVTX)
        pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "S_ISVTX");
    intptr_t mode0 = mode;
    mode &= ~(S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX);
    if (mode != 0 || mode0 == 0)
        fprintf(stream, "%s0x%x", (pos == 0? "": " | "), mode);
}

static void write_prot(FILE *stream, intptr_t prot)
{
    if (prot == PROT_NONE)
    {
        fputs("PROT_NONE", stream);
        return;
    }
    size_t pos = 0;
    if (prot & PROT_READ)
        pos += fputs("PROT_READ", stream);
    if (prot & PROT_WRITE)
        pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "PROT_WRITE");
    if (prot & PROT_EXEC)
        pos += fprintf(stream, "%s%s", (pos == 0? "": " | "), "PROT_EXEC");
    prot &= ~(PROT_READ | PROT_WRITE | PROT_EXEC);
    if (prot != 0)
        fprintf(stream, "%s0x%x", (pos == 0? "": " | "), prot);
}

static void write_signal(FILE *stream, intptr_t sig)
{
    switch (sig)
    {
        case SIGHUP:
            fputs("SIGHUP", stream);
            break;
        case SIGINT:
            fputs("SIGINT", stream);
            break;
        case SIGQUIT:
            fputs("SIGQUIT", stream);
            break;
        case SIGFPE:
            fputs("SIGFPE", stream);
            break;
        case SIGKILL:
            fputs("SIGKILL", stream);
            break;
        case SIGSEGV:
            fputs("SIGSEGV", stream);
            break;
        case SIGPIPE:
            fputs("SIGPIPE", stream);
            break;
        case SIGALRM:
            fputs("SIGALRM", stream);
            break;
        case SIGTERM:
            fputs("SIGTERM", stream);
            break;
        case SIGUSR1:
            fputs("SIGUSR1", stream);
            break;
        case SIGUSR2:
            fputs("SIGUSR2", stream);
            break;
        case SIGCHLD:
            fputs("SIGCHLD", stream);
            break;
        case SIGCONT:
            fputs("SIGCONT", stream);
            break;
        case SIGSTOP:
            fputs("SIGSTOP", stream);
            break;
        case SIGBUS:
            fputs("SIGBUS", stream);
            break;
        case SIGPOLL:
            fputs("SIGPOLL", stream);
            break;
        case SIGPROF:
            fputs("SIGPROF", stream);
            break;
        case SIGSYS:
            fputs("SIGSYS", stream);
            break;
        case SIGTRAP:
            fputs("SIGTRAP", stream);
            break;
        default:
            fprintf(stream, "%d", sig);
            break;
    }
}

/*
 * PRINT: Print syscall information to stderr.
 */
int hook(int callno, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t *result)
{
    FILE *stream = stderr;
    intptr_t args[] = {arg1, arg2, arg3, arg4, arg5, arg6, 0};
    
    if (callno >= 0 && callno < sizeof(syscalls) / sizeof(syscalls[0]))
    {
        const struct syscall_s *info = syscalls + callno;

        write_color(stream, COLOR_YELLOW);
        fputs(info->name, stream);
        write_color(stream, COLOR_CLEAR);
        fputc('(', stream);

        bool first = true;
        for (unsigned i = 0; i < 6; i++)
        {
            if (info->args[i].kind == ARG_NONE)
                break;
            if (!first)
                fputs(", ", stream);
            first = false;
            fprintf(stream, "%s=(", info->args[i].name);
            write_color(stream, COLOR_GREEN);
            fputs(info->args[i].type, stream);
            write_color(stream, COLOR_CLEAR);
            fputc(')', stream);
            write_color(stream, COLOR_RED);
            switch (info->args[i].kind)
            {
                case ARG_POINTER:
                    fprintf(stream, "%p", (void *)args[i]);
                    break;
                case ARG_INTEGER:
                    fprintf(stream, "%ld", args[i]);
                    break;
                case ARG_STRING:
                    fputc('\"', stream);
                    fputs((const char *)args[i], stream);
                    fputc('\"', stream);
                    break;
                case ARG_BUFFER:
                {
                    size_t len = (size_t)args[i+1];
                    const uint8_t *buf = (const uint8_t *)args[i];
                    fputc('\"', stream);
                    for (size_t j = 0; j < len; j++)
                        write_byte(stream, buf[j]);
                    fputc('\"', stream);
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
                        fprintf(stream, "0x%x", mode);
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
                    fputs("???", stream);
                    break;
            }
            write_color(stream, COLOR_CLEAR);
        }
    }
    else
    {
        fprintf(stream, "syscall(callno=%d", callno);
        for (unsigned i = 0; i < 6; i++)
            fprintf(stderr, ", arg%d=0x%lx", i, args[i]);
    }
    fputs(")\n", stream);

    return -1;
}

/*
 * Initialization function.
 */
void init(void)
{
    setvbuf(stderr, NULL, _IOLBF, 0);
}

