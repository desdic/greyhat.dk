+++
title = "IO Smash the stack level 01"
date = "2016-01-26"
publishdate = "2016-01-26"
categories =["Security"]
tags = ["Wargames", "Binary"]
slug = "io-smashthestack-level-01"
project_url = "https://greyhat.dk/io-smashthestack-level-01"
type = "post"
description = "Walk-through"
image = "binary.png"
image_alt = "Binary pattern"
+++

A colleague of mine recommended playing wargames so I started on io.smashthestack.org and will write my findings. Please notice that I do not write the passwords for levels and you should really not just try to copy but understand the challanges yourself. You will only be cheating yourself of fun :)

## Level01
```sh
level1@io:~$ cd /levels/
level1@io:/levels$ ls -latr level01*
-r-sr-x--- 1 level2 level1 1184 Jan 13  2014 level01
```

No source provided so lets try to start it

```sh
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: 123
```

Its a passcode and I cleary didn't get 123 right. Lets fire it up in GDB and look at the source

```sh
level1@io:/levels$ gdb -q ./level01
Reading symbols from /levels/level01...(no debugging symbols found)...done.
(gdb) disassemble
YouWin       __bss_start  _edata       _end         _start       doit         exit         exitscanf    fscanf       main         prompt1      prompt2      puts         shell        skipwhite
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048080 <+0>:	push   $0x8049128
   0x08048085 <+5>:	call   0x804810f <puts>
   0x0804808a <+10>:	call   0x804809f <fscanf>
   0x0804808f <+15>:	cmp    $0x10f,%eax                  <------------ compare input with value
   0x08048094 <+20>:	je     0x80480dc <YouWin>
   0x0804809a <+26>:	call   0x8048103 <exit>
End of assembler dump.
(gdb) !echo "ibase=16; 10F"|bc
XXX
(gdb) r
Starting program: /levels/level01
Enter the 3 digit passcode to enter: XXX
Congrats you found it, now read the password for level2 from /home/level2/.pass
process 15848 is executing new program: /bin/bash
sh-4.2$ whoami
level1
```

It worked except that since I'm within GDB I didn't get the SUID. Running it outside GDB.

```sh
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: XXX
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.2$ whoami
level2
sh-4.2$ cat /home/level2/.pass
XXXXXXXXXXXXXXXX
```


