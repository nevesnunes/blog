---
layout: post
title: Filename Hook
date: 2021-07-22 18:46:03 +0100
tags:
    - filesystems
    - linkers
---

{% include custom.html %}

To workaround a filesystem feature, I decided to try dynamic preloading, bumping into a bunch of libc corners...

## Analysis

In this case, a git repository was failing to checkout:

```
fatal: unable to checkout working tree
warning: Clone succeeded, but checkout failed.
You can inspect what was checked out with 'git status'
and retry with 'git restore --source=HEAD :/'
```

If we run with `strace -e file`:

```
mkdir("foo.", 0777) = -1 EINVAL (Invalid argument)
```

Same error could be reproduced with a simple `mkdir -p foo.`.

The filesystem was NTFS, where implementations may [disallow creating files with a dot at the end of the filename](https://superuser.com/questions/585097/why-does-ntfs-disallow-the-use-of-trailing-periods-in-directory-names). While Windows APIs support prefixing a path with `\\?\` to [disable all string parsing and passthrough to the filesystem](https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-file-namespaces), Linux has NTFS-3G, which [honors the disallow behaviour](https://sourceforge.net/p/ntfs-3g/ntfs-3g/ci/17b56ccfa2334ec905b80b81b151c54a263a6d61/) when mount option `windows_names` is set, so the boring solution is to mount without it.

Is there another way around this? Well, NTFS-3G uses the libc to interface with the filesystem, so we should be able to hook the relevant functions using LD_PRELOAD. The idea is to clean the filename, so that it no longer ends with a dot. I chose suffixing an underscore to it, since it's relatively uncommon for names to end with `._`.

## Covering relevant functions

We want all functions that expect a filename as argument. In particular, the signature is needed to know which arguments to pass when calling the original function with the cleaned filename, via `dlsym(RTLD_NEXT, "foo")`. The laziest approach I could think of was to grab the [single page glibc documentation](https://www.gnu.org/software/libc/manual/html_mono/libc.html), which conveniently describes functions in a greppable manner, which we filter by parameter names:

```bash
grep 'Function:' libc.html | grep -i '(.*\(.*filename\|path\).*)'
```

Then we massage these signatures into hook functions (an example for `mkdir()`):

```c
int mkdir(const char *filename, mode_t mode) {
    filename = clean(filename, "mkdir");

    int (*original)(const char *filename, mode_t mode);
    original = dlsym(RTLD_NEXT, "mkdir");
    return (*original)(filename, mode);
}
```

Except when it's not that direct.

### Variadic arguments

While C allows defining varargs, there's no way to delegate them to another call without explicitly passing the arguments. Ok, so we parse them. But how many? It's implementation specific... it can end with a null byte, or with any other arbitrary criteria.

One case is `open()`, which can have an optional argument:

> The argument mode is used only when a file is created.
>   - https://www.gnu.org/software/libc/manual/html_node/Opening-and-Closing-Files.html

A better clarification of how that file creation check is done:

> `mode` specifies the permissions to use in case a new file is created. This argument must be supplied when O_CREAT is specified in flags; if O_CREAT is not specified, then mode is ignored.
>   - https://linux.die.net/man/2/open

Alternatively, with a simple stat check, that one ends up as:

```c
struct stat stat_buf;
if (stat(filename, &stat_buf) == 0) {
    // File exists, ignore mode.
    return (*original)(filename, flags);
} else {
    va_list argp;
    va_start(argp, flags);
    mode_t mode = va_arg(argp, mode_t);
    va_end(argp);

    return (*original)(filename, flags, mode);
}
```

But there are trickier cases, such as `execl()`, where we have to deal with zero or more arguments:

> This is similar to execv, but the argv strings are specified
> individually instead of as an array. A null pointer must be passed
> as the last such argument.
>   - https://www.gnu.org/software/libc/manual/html_node/Executing-a-File.html

In order to pass them explicitly, we have to compromise with a fixed number of handled cases:

```c
va_list argp;
va_start(argp, arg0);
char *argX = va_arg(argp, char *);
char **args[20];
int i = 0;
while (*argX != '\0' && i < 20) {
    args[i] = &argX;
    argX = va_arg(argp, char *);
    i++;
}
va_end(argp);

switch (i) {
case 1:
    return (*original)(filename, arg0, *args[0]);
case 2:
    return (*original)(filename, arg0, *args[0], *args[1]);
case 3:
    return (*original)(filename, arg0, *args[0], *args[1], *args[2]);
// [...]
default:
    return (*original)(filename, arg0);
}
```

Unfortunately the [\__VA_ARGS__ variadic macro](https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html) is of no use here, since we would still need to explicitly pass the arguments to it.

An alternative would be to [setup the call in assembly](https://stackoverflow.com/a/61474680/8020917), with all its portability caveats.

### Wrappers for wrappers

Until now, we were assuming that the syscall names match the function symbols exposed by glibc, but we can find many exceptions.

As an example, compare these syscalls:

```
mkdir("foo._", 0777) = 0
openat(AT_FDCWD, "foo.", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY) = -1 ENOENT (No such file or directory)
```

Against the library calls output by `ltrace mkdir -p foo/bar`:

```
mkdir("foo", 0777) = 0
__open_2(0x7fffded3e73e, 0x30900, 1, 0) = 3
```

Why does ltrace report such a specific symbol for opening a file? Is it directly called by rm? Let's follow in the debugger. For convenience, I've installed the glibc debuginfo for my Linux distro.

```
pwndbg> catch syscall openat
Catchpoint 1 (syscall 'openat' [257])
pwndbg> run -p adsf/asdf
...
 ► f 0     7ffff7fec278 __open_nocancel+56
   f 1     7ffff7fdc3da _dl_sysdep_read_whole_file+42
   f 2     7ffff7fe39a4 _dl_load_cache_lookup+372
   f 3     7ffff7fd5338 _dl_map_object+1656
   f 4     7ffff7fd9a05 openaux+53
   f 5     7ffff7fe903e _dl_catch_exception+110
   f 6     7ffff7fd9e2e _dl_map_object_deps+1054
   f 7     7ffff7fcf1f3 dl_main+7283
   f 8     7ffff7fe7fe7 _dl_sysdep_start+935
   f 9     7ffff7fcd0ef _dl_start+655
   f 10     7ffff7fcd0ef _dl_start+655
```

We're still in libc startup, let's move forward:

```
   In file: /usr/include/bits/fcntl2.h
   52   }
   53       return __open_alias (__path, __oflag, __va_arg_pack ());
   54     }
   55
   56   if (__va_arg_pack_len () < 1)
 ► 57     return __open_2 (__path, __oflag);
...
 ► f 0     7ffff7e8703b open64+91
   f 1     555555559e77 savewd_chdir+503
   f 2     55555555ffe9 make_dir_parents.constprop+745
   f 3     5555555602dd process_dir+77
   f 4     55555555711e main+1294
   f 5     7ffff7dbdb75 __libc_start_main+213
```

If we disassemble `savewd_chdir()` and check the instruction before the address in frame 1:

```
pwndbg> disass savewd_chdir
...
0x0000555555559e72 <+498>:   call   0x555555556710 <__open_2@plt>
```

The corresponding symbol table contains the source filename:

```
pwndbg> python print(gdb.lookup_symbol("__open_2")[0].symtab.fullname())
/usr/src/debug/glibc-2.33-18.fc34.x86_64/io/open_2.c
```

Where we can find our signature:

```
int __open_2 (const char *file, int oflag)
```

And a brief comment with its purpose:

> _FORTIFY_SOURCE wrapper for open.

There's plenty of other hardening and compatibility wrappers to be found, as we can glance from a `objdump -T /lib/libc.so.6` and cross-validate against `extern` signatures or `strong_alias`/`weak_alias` macro expansions.

## Cleanup

Appending an underscore should be pretty simple...

```
mkdir("foo./bar", 0777) = -1 ENOENT (No such file or directory)
```

Of course, we need to handle each subpath, so let's use `strtok()` to split by `/`:

```
segmentation fault (core dumped)
```

Hmm, let's check the core dump with `coredumpctl gdb "$(coredumpctl list | tail -n1 | awk '{print $5}')"`:

```
RBX  0x7ff6314002e3 ◂— '/selinux/config'
RDI  0x7ff6314002e0 ◂— 'etc/selinux/config'
...
 ► 0x7ff6312a1ddb <strtok_r+75>    mov    byte ptr [rbx], 0
```

We see an attempt at writing to the filename passed as the first argument via RDI to `strtok()`. If we lookup the section containing `0x7ff6314002e0`:

```
pwndbg> maintenance info sections
...
[44]     0x7ff631400000->0x7ff631407000 at 0x0003f000: load28 ALLOC READONLY
```

Oh right, `strtok()` mutates the string passed to it, so we need a mutable copy.

What else? Let's try `rm -f foo`:

```
rm: failed to get attributes of '/': No such file or directory
```

Here's ltrace with vs. without our hooks:

```diff
-lstat(0x5641e64a824b, 0x7fff9f9f4150, 0x7fca8ee6d380, 1) = 0xffffffff
+lstat(0x556c3bee324b, 0x7fffd7b839c0, 0x7f7fcdd41380, 1) = 0
```

Turns out that sometimes we want to fallback to a more informative `strace -k`:

```diff
-lstat("", 0x7fffd8961c10)               = -1 ENOENT (No such file or directory)
-  > /usr/lib64/libc-2.33.so() [0x100dba]
-  > /home/fn/code/snippets/preload/ntfs_clean_name.so(lstat+0x59) [0x2e20]
-  > /usr/bin/rm(main+0x88c) [0x319c]
-  > /usr/lib64/libc-2.33.so() [0x27b74]
-  > /usr/bin/rm(_start+0x2d) [0x420d]
+newfstatat(AT_FDCWD, "/", {st_mode=S_IFDIR|0555, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
+  > /usr/lib64/libc-2.33.so() [0xf080e]
+  > /usr/bin/rm(main+0x88c) [0x319c]
+  > /usr/lib64/libc-2.33.so() [0x27b74]
+  > /usr/bin/rm(_start+0x2d) [0x420d]
```

We are calling another `lstat()` wrapper in libc, as seen in the different reported addresses (`0xf080e vs. 0x100dba`). Let's inspect `main+0x88c`, but to break in the debugger, we want to adjust to the address at the beginning of the call instruction bytes:

```
# Although 0x88c = 2188, the call is at 2184
0x0000555555557198 <+2184>:  call   0x555555556650 <lstat@plt>

# Let's break on that address then
gdb -ex 'b main' -ex 'run -r foo' -ex 'b *(0x555555554000 + 0x319c - 4)' -ex 'c' rm
...
   0x555555556650 <lstat@plt>       endbr64
   0x555555556654 <lstat@plt+4>     bnd jmp qword ptr [rip + 0xc7ed] <lstat64>
    ↓
 ► 0x7ffff7eb27e0 <lstat64>         endbr64
    ↓
   0x7ffff7eb27e7 <lstat64+7>       mov    ecx, 0x100
   0x7ffff7eb27ec <lstat64+12>      mov    rsi, rdi
   0x7ffff7eb27ef <lstat64+15>      mov    edi, 0xffffff9c
   0x7ffff7eb27f4 <lstat64+20>      jmp    fstatat64 <fstatat64>
    ↓
   0x7ffff7eb2800 <fstatat64>       endbr64
```

Turns out I was delegating to `__lxstat()`, as I misinterpreted this comment:

> The 'stat', 'fstat', 'lstat' functions have to be handled special since
> even while not compiling the library with optimization calls to these
> functions in the shared library must reference the 'xstat' etc
> functions. We have to use macros but we cannot define them in the
> normal headers since on user level we must use real functions.
>   - https://code.woboq.org/userspace/glibc/include/sys/stat.h.html

The correct behaviour is to just delegate to `lstat()`.

Almost there...

```
readlink("/usr/bin/rm", 0x7ffdf3a96500, 1023) = -1 EINVAL (Invalid argument)
```

We just need to compare traces with vs. without our hooks:

```diff
-newfstatat(AT_FDCWD, "", 0x7ffe91509720, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
+newfstatat(AT_FDCWD, "/", {st_mode=S_IFDIR|0555, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
```

Since `strtok()` consumes delimiters, a path consisting only of `/` would resolve to an empty string, so we need to handle that case separately.

---

After these fixes, we arrive at the overall logic to implement:

- Allocate memory for containing the characters of the original filename plus an extra character for each subpath name;
- Make a mutable copy for `strtok()`;
- Don't clean special name-inode maps (i.e. `.` and `..`);
- If the pathname only contains delimiters, then return `/`;
- We don't care about additional trailing delimiters, so we can just add a single `/` between subpaths;

## Source code

Available in a [git repository](https://github.com/nevesnunes/env/blob/master/common/code/snippets/preload/ntfs_clean_name.c).

Try it out:

```bash
gcc ntfs_clean_name.c -fPIC -shared -ldl -o ntfs_clean_name.so
LD_PRELOAD=./ntfs_clean_name.so touch foo.
```

## Further work

- Some hooks may be missing, but simple use cases should be already covered: creating, accessing, and removing files. I've considered parsing the remaining signatures with tree-sitter, but it turns out that some tokens aren't recognized by its C grammar, such as variadic arguments;
- For statically built apps, instead of LD_PRELOAD, we could use [ptrace](https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/);
