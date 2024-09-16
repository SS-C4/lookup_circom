//    signal input hin[256];
//    signal input inp[512];
//    signal output out[256];
pragma circom 2.0.0;

include "random_tables.circom";

function rrot(x, n) {
    return ((x >> n) | (x << (32-n))) & 0xFFFFFFFF;
}

function bsigma0(x) {
    // return rrot(x,2) ^ rrot(x,13) ^ rrot(x,22);
    var x_nibbles[8];
    for (var i=0; i<8; i++) {
        x_nibbles[i] = (x >> 4*i) & 15;
    }
    var rot1_nibbles[8];
    var rot2_nibbles[8];
    var rot3_nibbles[8];
    for (var i=0; i<8; i++) {
        rot1_nibbles[i] = table_function(x_nibbles[i], 20);
        rot2_nibbles[i] = table_function(x_nibbles[i], 21);
        rot3_nibbles[i] = table_function(x_nibbles[i], 22);
    }
    var out_nibbles[8];
    for (var i=0; i<8; i++) {
        out_nibbles[i] = rot1_nibbles[i] ^ rot2_nibbles[i] ^ rot3_nibbles[i];
    }
    var out = 0;
    for (var i=0; i<8; i++) {
        out += out_nibbles[i] << 4*i;
    }
    return out;
}

function bsigma1(x) {
    // return rrot(x,6) ^ rrot(x,11) ^ rrot(x,25);
    var x_nibbles[8];
    for (var i=0; i<8; i++) {
        x_nibbles[i] = (x >> 4*i) & 15;
    }
    var rot1_nibbles[8];
    var rot2_nibbles[8];
    var rot3_nibbles[8];
    for (var i=0; i<8; i++) {
        rot1_nibbles[i] = table_function(x_nibbles[i], 30);
        rot2_nibbles[i] = table_function(x_nibbles[i], 31);
        rot3_nibbles[i] = table_function(x_nibbles[i], 32);
    }
    var out_nibbles[8];
    for (var i=0; i<8; i++) {
        out_nibbles[i] = rot1_nibbles[i] ^ rot2_nibbles[i] ^ rot3_nibbles[i];
    }
    var out = 0;
    for (var i=0; i<8; i++) {
        out += out_nibbles[i] << 4*i;
    }
    return out;
}

function ssigma0(x) {
    // out = rrot(x,7) ^ rrot(x,18) ^ (x >> 3);
    var x_nibbles[8];
    for (var i=0; i<8; i++) {
        x_nibbles[i] = (x >> 4*i) & 15;
    }
    var rot1_nibbles[8];
    var rot2_nibbles[8];
    var rsh1_nibbles[8];
    for (var i=0; i<8; i++) {
        rot1_nibbles[i] = table_function(x_nibbles[i], 00);
        rot2_nibbles[i] = table_function(x_nibbles[i], 01);
        rsh1_nibbles[i] = table_function(x_nibbles[i], 02);
    }
    var out_nibbles[8];
    for (var i=0; i<8; i++) {
        out_nibbles[i] = rot1_nibbles[i] ^ rot2_nibbles[i] ^ rsh1_nibbles[i];
    }
    var out = 0;
    for (var i=0; i<8; i++) {
        out += out_nibbles[i] << 4*i;
    }
    return out;
}

function ssigma1(x) {
    // return rrot(x,17) ^ rrot(x,19) ^ (x >> 10);
    var x_nibbles[8];
    for (var i=0; i<8; i++) {
        x_nibbles[i] = (x >> 4*i) & 15;
    }
    var rot1_nibbles[8];
    var rot2_nibbles[8];
    var rsh1_nibbles[8];
    for (var i=0; i<8; i++) {
        rot1_nibbles[i] = table_function(x_nibbles[i], 10);
        rot2_nibbles[i] = table_function(x_nibbles[i], 11);
        rsh1_nibbles[i] = table_function(x_nibbles[i], 12);
    }
    var out_nibbles[8];
    for (var i=0; i<8; i++) {
        out_nibbles[i] = rot1_nibbles[i] ^ rot2_nibbles[i] ^ rsh1_nibbles[i];
    }
    var out = 0;
    for (var i=0; i<8; i++) {
        out += out_nibbles[i] << 4*i;
    }
    return out;
}

function Maj(x, y, z) {
    return (x&y) ^ (x&z) ^ (y&z);
}

function Ch(x, y, z) {
    return (x & y) ^ ((0xFFFFFFFF ^x) & z);
}

function sha256K(i) {
    var k[64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    return k[i];
}

function sha256compression(hin, inp) {
    var H[8];
    var a;
    var b;
    var c;
    var d;
    var e;
    var f;
    var g;
    var h;
    var out[64];
    for (var i=0; i<8; i++) {
        H[i] = 0;
        for (var j=0; j<8; j++) {
            H[i] += hin[i*8+j] << 4*j;
        }
    }
    a=H[0];
    b=H[1];
    c=H[2];
    d=H[3];
    e=H[4];
    f=H[5];
    g=H[6];
    h=H[7];
    var w[64];
    var T1;
    var T2;
    for (var i=0; i<64; i++) {
        if (i<16) {
            w[i]=0;
            for (var j=0; j<8; j++) {
                w[i] +=  inp[i*8+7-j] << 4*j;
            }
        } else {
            w[i] = (ssigma1(w[i-2]) + w[i-7] + ssigma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF;
        }
        T1 = (h + bsigma1(e) + Ch(e,f,g) + sha256K(i) + w[i]) & 0xFFFFFFFF;
        T2 = (bsigma0(a) + Maj(a,b,c)) & 0xFFFFFFFF;

        h=g;
        g=f;
        f=e;
        e=(d+T1) & 0xFFFFFFFF;
        d=c;
        c=b;
        b=a;
        a=(T1+T2) & 0xFFFFFFFF;

    }
    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;
    for (var i=0; i<8; i++) {
        for (var j=0; j<8; j++) {
            out[i*8+7-j] = (H[i] >> 4*j) & 15;
        }
    }
    return out;
}
