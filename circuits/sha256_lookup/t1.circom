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
// include "ch.circom";

include "random_tables.circom";

template Ch_t_Lookup() {
    signal input a[8];
    signal input b[8];
    signal input c[8];
    signal output out[8];
    
    // out = a&b ^ (!a)&c

    // Extras
    signal output xor_I[8];
    signal output xor_A[8];

    signal output not_I[8];
    signal output not_A[8];

    signal output and_I[16];
    signal output and_A[16];

    // Not
    for (var k=0; k<8; k++) {
        not_I[k] <== a[k];
        not_A[k] <-- not_function(a[k]);
    }

    // Ands
    for (var k=0; k<8; k++) {
        and_I[k] <== a[k] + b[k] * 16;
        and_A[k] <-- and_function(a[k] + b[k] * 16);

        and_I[k+8] <-- not_A[k] + c[k] * 16;
        and_A[k+8] <-- and_function(not_A[k] + c[k] * 16);
    }

    // XOR
    for (var k=0; k<8; k++) {
        xor_I[k] <== and_A[k] + and_A[k+8] * 16;
        xor_A[k] <-- xor_function(and_A[k] + and_A[k+8] * 16);
    }

    // Output
    for (var k=0; k<8; k++) {
        out[k] <-- xor_A[k];
    }
}

template BigSigma_1_Lookup() {
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
        random_A_1[0][k] <-- table_function(in[k], 30);
        random_A_1[1][k] <-- table_function(in[k], 31);
        random_A_1[2][k] <-- table_function(in[k], 32);
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

template T1() {
    signal input h[8];
    signal input e[8];
    signal input f[8];
    signal input g[8];
    signal input k[8];
    signal input w[8];
    signal output out[8];

    var ki;

    // Extras
    signal output random_I_1[3][8];
    signal output random_A_1[3][8];

    signal output xor_I[24];
    signal output xor_A[24];

    signal output not_I[8];
    signal output not_A[8];

    signal output and_I[16];
    signal output and_A[16];

    signal output range_I[8];
    signal output range_A[8];

    component ch = Ch_t_Lookup();
    component bigsigma1 = BigSigma_1_Lookup();

    for (ki=0; ki<8; ki++) {
        bigsigma1.in[ki] <== e[ki];
        ch.a[ki] <== e[ki];
        ch.b[ki] <== f[ki];
        ch.c[ki] <== g[ki];
    }

    // Update fixed I and A for ch
    for (ki=0; ki<8; ki++) {
        not_I[ki] <-- ch.not_I[ki];
        not_A[ki] <-- ch.not_A[ki];

        and_I[ki] <-- ch.and_I[ki];
        and_A[ki] <-- ch.and_A[ki];
        and_I[ki+8] <-- ch.and_I[ki+8];
        and_A[ki+8] <-- ch.and_A[ki+8];

        xor_I[ki] <-- ch.xor_I[ki];
        xor_A[ki] <-- ch.xor_A[ki];
    }

    // Update I and A for bigsigma1
    for (ki=0; ki<8; ki++) {
        random_I_1[0][ki] <-- bigsigma1.random_I_1[0][ki];
        random_I_1[1][ki] <-- bigsigma1.random_I_1[1][ki];
        random_I_1[2][ki] <-- bigsigma1.random_I_1[2][ki];
        random_A_1[0][ki] <-- bigsigma1.random_A_1[0][ki];
        random_A_1[1][ki] <-- bigsigma1.random_A_1[1][ki];
        random_A_1[2][ki] <-- bigsigma1.random_A_1[2][ki];
    }

    for (ki=0; ki<16; ki++) {
        xor_I[ki+8] <-- bigsigma1.xor_I[ki];
        xor_A[ki+8] <-- bigsigma1.xor_A[ki];
    }

    component sum = BinSum_Lookup(5);
    for (ki=0; ki<8; ki++) {
        sum.in[0][ki] <== h[ki];
        sum.in[1][ki] <== bigsigma1.out[ki];
        sum.in[2][ki] <== ch.out[ki];
        sum.in[3][ki] <== k[ki];
        sum.in[4][ki] <== w[ki];
    }

    // Update range I and A
    for (ki=0; ki<8; ki++) {
        range_I[ki] <-- sum.range_I[ki];
        range_A[ki] <-- sum.range_A[ki];
    }

    for (ki=0; ki<8; ki++) {
        out[ki] <-- sum.out[ki];
    }
}
