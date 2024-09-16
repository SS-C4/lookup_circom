/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

include "../binsum.circom";
// include "sigma.circom";
// include "maj.circom";

template Maj_Lookup() {
    signal input a[8];
    signal input b[8];
    signal input c[8];
    signal output out[8];
    
    // out = a&b ^ a&c ^ b&c

    // Extras
    signal output xor_I[16];
    signal output xor_A[16];

    signal output and_I[24];
    signal output and_A[24];

    // Ands
    for (var k=0; k<8; k++) {
        and_I[k] <== a[k] + b[k] * 16;
        and_A[k] <-- and_function(a[k] + b[k] * 16);

        and_I[k+8] <-- a[k] + c[k] * 16;
        and_A[k+8] <-- and_function(a[k] + c[k] * 16);

        and_I[k+16] <-- b[k] + c[k] * 16;
        and_A[k+16] <-- and_function(b[k] + c[k] * 16);
    }

    // XOR
    for (var k=0; k<8; k++) {
        xor_I[k] <-- and_A[k] + and_A[k+8] * 16;
        xor_A[k] <-- xor_function(and_A[k] + and_A[k+8] * 16);

        xor_I[k+8] <-- xor_A[k] + and_A[k+16] * 16;
        xor_A[k+8] <-- xor_function(xor_A[k] + and_A[k+16] * 16);
    }

    // Output
    for (var k=0; k<8; k++) {
        out[k] <-- xor_A[k+8];
    }
}

template BigSigma_0_Lookup() {
    signal input in[8];
    signal output out[8];
    var k;

    // Extras
    signal output random_I_1[3][8];
    signal output random_A_1[3][8];

    signal output xor_I[16];
    signal output xor_A[16];

    // Accumulation
    for (k=0; k<8; k++) {
        random_I_1[0][k] <-- in[k];
        random_I_1[1][k] <-- in[k];
        random_I_1[2][k] <-- in[k];
    }
    for (k=0; k<8; k++) {
        random_A_1[0][k] <-- table_function(in[k], 20);
        random_A_1[1][k] <-- table_function(in[k], 21);
        random_A_1[2][k] <-- table_function(in[k], 22);
    }

    for (k=0; k<8; k++) {
        xor_I[k] <-- random_A_1[0][k] + random_A_1[1][k] * 16;
        xor_A[k] <-- random_A_1[0][k] ^ random_A_1[1][k];

        xor_I[8 + k] <-- random_A_1[2][k] + xor_A[k] * 16;
        xor_A[8 + k] <-- random_A_1[2][k] ^ xor_A[k];
    }

    for (k=0; k<8; k++) {
        out[k] <-- xor_A[8 + k];
    }
}

template T2() {
    signal input a[8];
    signal input b[8];
    signal input c[8];
    signal output out[8];
    var k;

    // Extras
    signal output random_I_1[3][8];
    signal output random_A_1[3][8];

    signal output and_I[24];
    signal output and_A[24];

    signal output xor_I[32];
    signal output xor_A[32];

    signal output range_I[8];
    signal output range_A[8];

    component bigsigma0 = BigSigma_0_Lookup();
    component maj = Maj_Lookup();
    for (k=0; k<8; k++) {
        bigsigma0.in[k] <== a[k];
        maj.a[k] <== a[k];
        maj.b[k] <== b[k];
        maj.c[k] <== c[k];
    }

    // Update bigsigma0 I and A
    for (k=0; k<8; k++) {
        random_I_1[0][k] <-- bigsigma0.random_I_1[0][k];
        random_I_1[1][k] <-- bigsigma0.random_I_1[1][k];
        random_I_1[2][k] <-- bigsigma0.random_I_1[2][k];
        random_A_1[0][k] <-- bigsigma0.random_A_1[0][k];
        random_A_1[1][k] <-- bigsigma0.random_A_1[1][k];
        random_A_1[2][k] <-- bigsigma0.random_A_1[2][k];
    }

    for (k=0; k<16; k++) {
        xor_I[k] <-- bigsigma0.xor_I[k];
        xor_A[k] <-- bigsigma0.xor_A[k];
    }

    // Update maj I and A
    for (k=0; k<24; k++) {
        and_I[k] <-- maj.and_I[k];
        and_A[k] <-- maj.and_A[k];
    }

    for (k=0; k<16; k++) {
        xor_I[16 + k] <-- maj.xor_I[k];
        xor_A[16 + k] <-- maj.xor_A[k];
    }

    component sum = BinSum_Lookup(2);

    for (k=0; k<8; k++) {
        sum.in[0][k] <== bigsigma0.out[k];
        sum.in[1][k] <== maj.out[k];
    }

    // Update sum I and A
    for (k=0; k<8; k++) {
        range_I[k] <-- sum.range_I[k];
        range_A[k] <-- sum.range_A[k];
    }

    for (k=0; k<8; k++) {
        out[k] <-- sum.out[k];
    }
}
