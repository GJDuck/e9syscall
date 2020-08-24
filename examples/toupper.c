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
 * TOUPPER: Convert writes to upper case.
 */
int hook(int callno, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t *result)
{
    int fd = (int)arg1;
    if (callno != SYS_write || (fd != STDOUT_FILENO && fd != STDERR_FILENO))
        return -1;

    const char *buf0 = (const char *)arg2;
    size_t count     = (size_t)arg3;
    
    char buf1[count];
    for (size_t i = 0; i < count; i++)
    {
        char c = buf0[i];
        buf1[i] = (c >= 'a' && c <= 'z'? 'A' + (c - 'a'): c);
    }
    *result = syscall(SYS_write, fd, buf1, count);

    return 0;       // syscall replaced
}

