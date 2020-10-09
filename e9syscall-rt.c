/*
 *        ___                          _ _ 
 *   ___ / _ \ ___ _   _ ___  ___ __ _| | |
 *  / _ \ (_) / __| | | / __|/ __/ _` | | |
 * |  __/\__, \__ \ |_| \__ \ (_| (_| | | |
 *  \___|  /_/|___/\__, |___/\___\__,_|_|_|
 *                 |___/ 
 *
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

#include "e9syscall.h"

#define STRING(x)   STRING_2(x)
#define STRING_2(x) #x

/*
 * System call implementation.
 */
asm
(
    ".globl syscall\n"
    "syscall:\n"

    // Disallow syscalls that MUST execute in the original context:
    "cmp $" STRING(SYS_rt_sigreturn) ",%eax\n"
    "je .Lno_sys\n"
    "cmp $" STRING(SYS_clone) ",%eax\n"
    "je .Lno_sys\n"

    // Convert SYSV -> SYSCALL ABI:
    "mov %edi,%eax\n"
    "mov %rsi,%rdi\n"
    "mov %rdx,%rsi\n"
    "mov %rcx,%rdx\n"
    "mov %r8,%r10\n"
    "mov %r9,%r8\n"
    "mov 0x8(%rsp),%r9\n"

    // Execute the system call:
    "syscall\n"

    "retq\n"

    // Handle errors:
    ".Lno_sys:\n"
    "mov $-" STRING(ENOSYS) ",%eax\n"
    "retq\n"
);

/*
 * Entry point.
 */
int intercept(intptr_t *rax, intptr_t rdi, intptr_t rsi, intptr_t rdx,
    intptr_t r10, intptr_t r8, intptr_t r9)
{
    int callno = (int)*rax;
    return hook(callno, rdi, rsi, rdx, r10, r8, r9, rax);
}

