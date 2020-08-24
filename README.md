# E9Syscall -- Linux System Call Interception

E9Syscall is a system call interception toolkit for `x86_64 Linux`.

Unlike other system call interception tools, E9Syscall does not
use `ptrace` or signal handlers (`SIGTRAP`).

## Usage

To use E9Syscall:

1. Implement your system call hook routine, e.g., in a file `hook.c`
2. Build a replacement `libc.so` using the command:

           ./e9syscall-build hook.c

This will build a modified `libc-hook.so` file which will call the hook
function every time a system call is executed.
To use, simply `LD_PRELOAD` the new library to replace the default,
e.g.:

        LD_PRELOAD=$PWD/libc-hook.so ls

The hook function has the following type signature:

        int hook(intptr_t arg1,
                 intptr_t arg2,
                 intptr_t arg3,
                 intptr_t arg4,
                 intptr_t arg5,
                 intptr_t arg6,
                 intptr_t *result);

The behaviour depends on the return value of the took function.

* If zero, the original system call will be executed as normal.
* If non-zero, the original system call will be replaced with
  by `*result`.

This allows for system calls to be instrumented (if zero)
or replaced (if non-zero), depending on the application.
This design was inspired by
[`syscall_intercept`](https://github.com/pmem/syscall_intercept).

## Example

For example, to log system calls to `stderr`:

        ./e9syscall-build examples/print.c
        LD_PRELOAD=$PWD/libc-print.so ls

See `examples/*.c` for other example hook functions.

## Limitations

For technical reasons, the `SYS_rt_sigreturn` and `SYS_clone` system calls cannot
be replaced.

The instrumentation code is somewhat limited, including:

* Cannot directly call libc functions (using system calls directly is OK)
* Cannot safely use/clobber floating point registers
* Stack may not be aligned

These limitations are inherited from the underlying E9Patch tool.

There is a chance that not call system calls can be intercepted, in which case
a warning will be printed.
However, it seems to work for all versions of libc tested so far.

## About

E9Syscall is a thin [E9Patch](https://github.com/GJDuck/e9patch) wrapper,
which is a powerful static binary rewriting tool for `x86_64 Linux`.

Basically, E9Syscall invokes E9Patch to replace all `syscall` instructions
with a call to a trampoline that invokes the hook function.
Since the interception does not use `ptrace` or signal handlers, it
is very fast.

## Related Tools

A few different system call interception libraries and tools have been
developed, including:

Library/Tool | Static? | `ptrace`? | `SIGTRAP`? 
--- | --- | --- | ---
[`syscall_intercept`](https://github.com/pmem/syscall_intercept) | &#9744; | &#9744; | &#9744;
[`SaBRe`](https://github.com/srg-imperial/SaBRe) | | &#9744; | &#9744; | &#9744;
[`libsystrap`](https://github.com/stephenrkell/libsystrap) | &#9744; | &#9744; | &#9745;
[`ptrace_do`](https://github.com/emptymonkey/ptrace_do) | &#9744; | &#9745; | &#9744;
[`fssb`](https://github.com/adtac/fssb) | &#9744; | &#9745; | &#9744;

Some tools use `ptrace` or signal handlers, however this is generally slow
since it involves context switching.
E9Syscall calls the hook function directly without one (or more)
context switches.

Both `syscall_intercept` and `SaBRe` avoid context switching by

1. replacing multiple instructions with jumps; and/or
2. replacing NOP-padding with jumps.

In fact, both `syscall_intercept` and `SaBRe` appear to be very similar tools.
However, this form of binary rewriting is potentially unsound, since it
assumes that both 1. and 2. are not affecting jump targets.
For limited applications such as system call interception, this is probably
OK in practice.

In contrast, E9Syscall uses E9Patch to safely replace `syscall` instructions with
calls to the hook function with modifying jump targets.
The method E9Patch uses are somewhat sophisticated, so please see
[here](https://github.com/GJDuck/e9patch) for more information.

## License

GPLv3

