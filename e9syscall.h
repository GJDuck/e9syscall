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

#ifndef __E9SYSCALL_H
#define __E9SYSCALL_H

#include <errno.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <syscall.h>

/*
 * The system call hook function to be defined by the user.  There are two
 * basic modes for the hook() function:
 *
 *  (1) [INSTRUMENTATION] The original system call will be executed with the
 *      original arguments after the hook() function has returned.  To enable this
 *      mode, the hook() function should return a non-zero value, and the
 *      *result value will be ignored.
 *
 *  (2) [REPLACEMENT] The original system call is replaced by the hook()
 *      function.  To enable this mode, the hook() function should return 0,
 *      and *result should be set to the replacement syscall return value.
 *
 * Note that only (1) can be used for the `rt_sigreturn' and `clone' syscalls.
 */
int hook(
	int callno,				// System call number.
    intptr_t arg1,          // System call argument #1
    intptr_t arg2,          // System call argument #2
    intptr_t arg3,          // System call argument #3
    intptr_t arg4,          // System call argument #4
    intptr_t arg5,          // System call argument #5
    intptr_t arg6,          // System call argument #6
    intptr_t *result);      // System call result

#endif      /* __E9SYSCALL_H */
