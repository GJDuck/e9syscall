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

#include "e9syscall.h"

/*
 * PASSTHRU: Does nothing.
 */
int hook(int callno, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t *result)
{
    if (callno == SYS_rt_sigreturn || callno == SYS_clone)
    {
        // These syscalls cannot be replaced.
        return -1;
    }

    *result = syscall(callno, arg1, arg2, arg3, arg4, arg5, arg6);
    return 0;
}

