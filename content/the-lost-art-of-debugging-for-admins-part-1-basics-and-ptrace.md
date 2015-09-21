+++
title = "The lost art of debugging for admins #part 1 - Basics and ptrace"
date ="2013-07-26"
publishdate ="2013-07-26"
categories = ["Debugging"]
tags = ["Assembly", "Linux", "strace"]
slug = "the-lost-art-of-debugging-for-admins-part-1-basics-and-ptrace"
project_url = "https://greyhat.dk/the-lost-art-of-debugging-for-admins-part-1-basics-and-ptrace"
type = "post"
+++

Basics
======

Its been a while since my last update. Been quite busy but also because
I didn't have anything to add. But lately I've have a urge to write a
series on how to debug on Linux (Works on other platforms as well).
Mostly because it seems that the younger generation (And even older) no
longer debugs their problems but just seek the nearest forum so see if
anyone else had the same issue.

First rule of debugging is: check logs or use verbose options.

Once that fails (Many programs have poor logging or inadequate
verbosity) you need to start looking at what the program actually does.
You could just use the "look at the source Luuk" but for several reasons
that might not be an option.

| 1) Looking though the source code is one thing, the other is
  understanding it (And you might not be familiar with the language or
  even be a programmer). Its quite time consuming and we all know once
  something stopped working we all have a CEO/Customer on our back.
|  2) Closed source will prevent you from looking at the source code
  (Almost)

So back to basics on how programs actually work. Programs call software
interrups. Its as simple as that .. lets examine that (You don't need to
be a programmer to understand this).

A simple Hello world program (Written in 32bit assembly language to keep
the calls to the kernel clean) to demonstrate it.

```asm
    .data 

    HelloWorldString:
        .ascii "Hello World\n"

    .text 

    .globl _start 

    _start:
        # Load all the arguments for write () 

        movl $4, %eax
        movl $1, %ebx
        movl $HelloWorldString, %ecx
        movl $12, %edx
        int $0x80

        # Need to exit the program 

        movl $1, %eax
        movl $0, %ebx
        int $0x80
```

I have split the \_start section up in 2 fragments. One for the actually
writing of "Hello world" and one for a clean exit. Notice the int $0x80
.. these are software interrups calling the kernel. Now there is about
300 calls you can make, thats about it.

First section

this is the actual sys\_write call as defined in
/usr/include/asm/unistd.h (it includes a unistd\_64.h or unistd\_32.h
depending your platform)

```asm
        movl $4, %eax
```

file descriptor (in this case 1=STDOUT)

```asm
        movl $1, %ebx 
```

pointer to where the string "Hello World" is located

```asm
        movl $HelloWorldString, %ecx
```

string length of "Hello World\\n"

```asm
        movl $12, %edx
```

call the kernel

```asm
        int $0x80
```

The equivalent call in C is the ssize_t write(int fd, const void *buf,
size_t count) (man 2 write)

Second section is just like the above

sys_close call (1)

```asm
        movl $1, %eax
```

exit status (0=all ok)

```asm
        movl $0, %ebx
```

Call kernel

```asm
        int $0x80
```

The equivalent call in C is the void _exit(int status) (man 2 exit)

So lets run the program

```sh
    # as -o HelloWorldProgram.o HelloWorldProgram.s
    # ld -o HelloWorldProgram HelloWorldProgram.o
    # ./HelloWorldProgram 
    Hello World
```

it works and that brings in the first tool for debugging.

strace(1) (trace system calls and signals)
==========================================

running HelloWorldProgram via strace shows that calls are made (Like we
didn't already knew :) )

```sh
    # strace ./HelloWorldProgram
    execve("./HelloWorldProgram", ["./HelloWorldProgram"], [/* 19 vars */]) = 0
    write(1, "Hello World\n", 12Hello World
    )           = 12
    _exit(0)                                = ?
```

So it starts the program, writes (our sys\_write) Hello World and then
exits (our sys\_close).

Now this is just a boring example so lets find a better use case.

Use case #1
===========

The use case for this debugging: A user cannot upload files via vsftpd
and complains. Nothing in the logs indicating other than the permissions
are wrong (Because of the "Create directory operation failed" error
message from the ftp client). So lets examine

```sh
    # quota -q
    # quota kgn
    Disk quotas for user kgn (uid 1008): none
```

Quotas seems fine and permissions are set to 777 (bad choice but this
was the case). I created a session by connecting to the ftp server

```sh
    # ftp 127.0.0.1
```

login and then find the process using ps in a second terminal. Now
connect strace to the vsftpd process (in my case pid 12047). Then try to
create a directory

```sh
    # strace -p 12047
    Process 12047 attached - interrupt to quit
    recvfrom(0, "MKD kgntest\r\n", 4096, MSG_PEEK, NULL, NULL) = 13
    read(0, "MKD kgntest\r\n", 13)          = 13
    getcwd("/", 4096)                       = 2
    mkdir("kgntest", 0777)                  = -1 EDQUOT (Disk quota exceeded)
    write(0, "550 Create directory operation f"..., 40) = 40
    getpid()                                = 3
    fcntl(3, F_SETLKW, {type=F_WRLCK, whence=SEEK_SET, start=0, len=0}) = 0
    write(3, "Thu Jul 25 20:48:20 2013 [pid 3]"..., 97) = 97
    fcntl(3, F_SETLK, {type=F_UNLCK, whence=SEEK_SET, start=0, len=0}) = 0
    rt_sigaction(SIGALRM, {0x4151d0, ~[RTMIN RT_1], SA_RESTORER, 0x7fed483d61e0}, NULL, 8) = 0
    alarm(300)                              = 230
    recvfrom(0, 
```

So lets go through the above example.

The command "mkdir kgntest" received via the network to the process

```sh
    recvfrom(0, "MKD kgntest\r\n", 4096, MSG_PEEK, NULL, NULL) = 13
```

Read the command

```sh
    read(0, "MKD kgntest\r\n", 13)          = 13
```

Change the directory to / (its chrooted)

```sh
    getcwd("/", 4096)                       = 2
```

The actual command for creating a directory (using 777) and this fails
with EDQUOT (Disk quota exceeded). So now we know that its the quota and
not the vsftpd server or permissions (The actual fix for this is
irrelevant)

```sh
    mkdir("kgntest", 0777)                  = -1 EDQUOT (Disk quota exceeded)
```

Use case #2
===========

Debugging a program that says its already running even though its not.

```sh
    # puppet agent --test
    notice: Run of Puppet configuration client already in progress; skipping
    # ps -ef|grep puppet
    root     11562 11281  0 14:08 pts/1    00:00:00 grep puppet
```

Great, lets fire up strace

```sh
    # strace puppet agent --test
    ... (a lot of output removed)
    mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb701c000
    _llseek(6, 0, [0], SEEK_CUR)            = 0
    read(6, "", 4096)                       = 0
    close(6)                                = 0
    munmap(0xb701c000, 4096)                = 0
    kill(0, SIG_0)                          = 0
    stat64("/var/lib/puppet/state/puppetdlock", {st_mode=S_IFREG|0644, st_size=0, ...}) = 0
    gettimeofday({1374840585, 567949}, NULL) = 0
    rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
    write(1, "\33[0;36mnotice: Run of Puppet con"..., 83notice: Run of Puppet configuration client already in progress; skipping) = 83
    write(1, "\n", 1
    )                       = 1
    time(NULL)                              = 1374840585
    send(5, "<29>Jul 26 14:09:45 puppet-agent"..., 105, MSG_NOSIGNAL) = 105
    rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
    rt_sigaction(SIGINT, {SIG_DFL, [INT], SA_RESTART}, {0xb76e9bf0, [], 0}, 8) = 0
    close(4)                                = 0
    munmap(0xb72fb000, 4096)                = 0
    close(3)                                = 0
    munmap(0xb72fc000, 4096)                = 0
    exit_group(1)                           = ?
```

so just before we get the error message "Run of Puppet configuration
client already in progress; skipping" there is a

```sh
    stat64("/var/lib/puppet/state/puppetdlock", {st_mode=S_IFREG|0644, st_size=0, ...}) = 0
```

So puppet seems to have crashed. It created a lock file in order not to
run more than once but when crashed it forgot to cleanup.

| So lets fix it

```sh
    # rm /var/lib/puppet/state/puppetdlock
```

Conclusion
==========

So now you know 2 things .. how programs actually works and how strace
can help you find the problem (strace (Linux), dtrace (BSD), truss (All
platforms))
