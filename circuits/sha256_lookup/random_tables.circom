pragma circom 2.0.0;

template xor_template() {
    signal input index;
    signal output out_nibble;
    var table[256];
    for (var i = 0; i < 256; i++) {
        var right = i % 16;
        var left = i >> 4;
        table[i] = left ^ right;
    }
    out_nibble <-- table[index];
}

function xor_function(index) {
    var right = index % 16;
    var left = index >> 4;
    return left ^ right;
}

// Table of size 256
template table_template(num) {
    signal input index;
    signal output out_nibble;
    var table1[256];
    for (var i = 0; i < 256; i++) {
        table1[i] = 1/(i + num * 512 + 1) % 16;
    }
    out_nibble <-- table1[index];
}

function table_function(index, num) {
    return 1/(index + num * 512 + 1) % 16;
}

// Legend of tables
// Table 00,01,02: ssigma0 (rot,rot,rsh)
// Table 10,11,12: ssigma1 (rot,rot,rsh)
// Table 20,21,22: bsigma0 (rot,rot,rot)
// Table 30,31,32: bsigma1 (rot,rot,rot)
// Table 4: Ch1
// Table 5: Ch2
// Table 6: Maj1
// Table 7: Maj2