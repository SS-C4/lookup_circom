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

// include "../binsum.circom";
// include "sigma.circom";

// template SigmaPlus() {
//     signal input in2[32];
//     signal input in7[32];
//     signal input in15[32];
//     signal input in16[32];
//     signal output out[32];
//     var k;

//     component sigma1 = SmallSigma(17,19,10);
//     component sigma0 = SmallSigma(7, 18, 3);
//     for (k=0; k<32; k++) {
//         sigma1.in[k] <== in2[k];
//         sigma0.in[k] <== in15[k];
//     }

//     component sum = BinSum(32, 4);
//     for (k=0; k<32; k++) {
//         sum.in[0][k] <== sigma1.out[k];
//         sum.in[1][k] <== in7[k];
//         sum.in[2][k] <== sigma0.out[k];
//         sum.in[3][k] <== in16[k];
//     }

//     for (k=0; k<32; k++) {
//         out[k] <== sum.out[k];
//     }
// }

template SmallSigma_Lookup_0() {
    signal input in[8];
    signal output out[8];
    var k;

    // Extras
    signal output random_I_0[3][8];
    signal output random_A_0[3][8];

    signal output xor_I[16];
    signal output xor_A[16];

    // Accumulation
    for (k=0; k<8; k++) {
        random_I_0[0][k] <-- in[k];
        random_I_0[1][k] <-- in[k];
        random_I_0[2][k] <-- in[k];
    }
    for (k=0; k<8; k++) {
        random_A_0[0][k] <-- table_function(in[k], 00);
        random_A_0[1][k] <-- table_function(in[k], 01);
        random_A_0[2][k] <-- table_function(in[k], 02);
    }

    for (k=0; k<8; k++) {
        xor_I[k] <-- random_A_0[0][k] + random_A_0[1][k] * 16;
        xor_A[k] <-- random_A_0[0][k] ^ random_A_0[1][k];

        xor_I[8 + k] <-- random_A_0[2][k] + xor_A[k] * 16;
        xor_A[8 + k] <-- random_A_0[2][k] ^ xor_A[k];
    }

    for (k=0; k<8; k++) {
        out[k] <-- xor_A[8 + k];
    }
}

template SmallSigma_Lookup_1() {
    signal input in[8];
    signal output out[8];
    var k;

    // Extras
    signal output random_I_0[3][8];
    signal output random_A_0[3][8];

    signal output xor_I[16];
    signal output xor_A[16];

    // Accumulation
    for (k=0; k<8; k++) {
        random_I_0[0][k] <-- in[k];
        random_I_0[1][k] <-- in[k];
        random_I_0[2][k] <-- in[k];
    }
    for (k=0; k<8; k++) {
        random_A_0[0][k] <-- table_function(in[k], 10);
        random_A_0[1][k] <-- table_function(in[k], 11);
        random_A_0[2][k] <-- table_function(in[k], 12);
    }

    for (k=0; k<8; k++) {
        xor_I[k] <-- random_A_0[0][k] + random_A_0[1][k] * 16;
        xor_A[k] <-- random_A_0[0][k] ^ random_A_0[1][k];

        xor_I[8 + k] <-- random_A_0[2][k] + xor_A[k] * 16;
        xor_A[8 + k] <-- random_A_0[2][k] ^ xor_A[k];
    }

    for (k=0; k<8; k++) {
        out[k] <-- xor_A[8 + k];
    }
}

template SigmaPlus() {
    signal input in2[8];
    signal input in7[8];
    signal input in15[8];
    signal input in16[8];
    signal output out[8];

    var k;

    // Extras
    signal output random_I_0[6][8];
    signal output random_A_0[6][8];

    signal output xor_I[32];
    signal output xor_A[32];

    signal output range_I[8];
    signal output range_A[8];

    component sigma1 = SmallSigma_Lookup_1();
    component sigma0 = SmallSigma_Lookup_0();

    for (k=0; k<8; k++) {
        sigma1.in[k] <== in2[k];
        sigma0.in[k] <== in15[k];
    }

    // Update random_I_0 and random_A_0
    for (k=0; k<8; k++) {
        random_I_0[0][k] <-- ssigma0.random_I_0[0][k];
        random_I_0[1][k] <-- ssigma0.random_I_0[1][k];
        random_I_0[2][k] <-- ssigma0.random_I_0[2][k];
        random_I_0[3][k] <-- ssigma1.random_I_0[0][k];
        random_I_0[4][k] <-- ssigma1.random_I_0[1][k];
        random_I_0[5][k] <-- ssigma1.random_I_0[2][k];

        random_A_0[0][k] <-- ssigma0.random_A_0[0][k];
        random_A_0[1][k] <-- ssigma0.random_A_0[1][k];
        random_A_0[2][k] <-- ssigma0.random_A_0[2][k];
        random_A_0[3][k] <-- ssigma1.random_A_0[0][k];
        random_A_0[4][k] <-- ssigma1.random_A_0[1][k];
        random_A_0[5][k] <-- ssigma1.random_A_0[2][k];
    }

    component sum = BinSum_Lookup(8, 4);

    for (k=0; k<8; k++) {
        sum.in[0][k] <== sigma1.out[k];
        sum.in[1][k] <== in7[k];
        sum.in[2][k] <== sigma0.out[k];
        sum.in[3][k] <== in16[k];
    }

    // Update range_I and range_A
    for (k=0; k<8; k++) {
        range_I[k] <-- sum.range_I[k];
        range_A[k] <-- sum.range_A[k];
    }

    for (k=0; k<8; k++) {
        out[k] <== sum.out[k];
    }
}