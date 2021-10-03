console.log('Tracing...');

const m = Process.enumerateModules()[0];
console.log('Base address: ' + m.base);

var char = -1
var char_i = -1
var is_correct = -1
Interceptor.attach(ptr(m.base.add(0x31c4)),
    function(args) {
        char = Memory.readU8(this.context.r13.add(this.context.rax))
        var rsi = this.context.rsi
        char_i = parseInt(rsi)
    }
);
Interceptor.attach(ptr(m.base.add(0x31cf)),
    function(args) {
        var rax = this.context.rax
        is_correct = parseInt(rax)
        console.log([char, char_i, is_correct])
        send([char, char_i, is_correct]);
    }
);
