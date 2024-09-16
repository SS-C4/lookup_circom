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

include "constants.circom";
include "t1.circom";
include "t2.circom";
include "../binsum.circom";
include "sigmaplus.circom";
include "sha256compression_function.circom";

include "../lookup.circom";
include "random_tables.circom";


template Sha256compression() {
    signal input hin[64];
    signal input inp[128];
    signal output out[64];
    signal a[65][8];
    signal b[65][8];
    signal c[65][8];
    signal d[65][8];
    signal e[65][8];
    signal f[65][8];
    signal g[65][8];
    signal h[65][8];
    signal w[64][8];


    var outCalc[64] = sha256compression(hin, inp);

    var i;
    for (i=0; i<64; i++) out[i] <-- outCalc[i];

    // Create tables and arrays
    // alpha
    var alpha[16];
    for (i=0; i<16; i++) alpha[i] = 1/(i + 131);

    // Random tables
    var random_T[12][256];
    for (var j=0; j<256; j++) {
        random_T[0][j] = table_function(j, 00);
        random_T[1][j] = table_function(j, 01);
        random_T[2][j] = table_function(j, 02);
        random_T[3][j] = table_function(j, 10);
        random_T[4][j] = table_function(j, 11);
        random_T[5][j] = table_function(j, 12);
        random_T[6][j] = table_function(j, 20);
        random_T[7][j] = table_function(j, 21);
        random_T[8][j] = table_function(j, 22);
        random_T[9][j] = table_function(j, 30);
        random_T[10][j] = table_function(j, 31);
        random_T[11][j] = table_function(j, 32);
    }

    var random_M[12][256];

    var random_I_0[6][8 * 48];
    var random_A_0[6][8 * 48];
    var random_I_1[6][8 * 64];
    var random_A_1[6][8 * 64];

    // Fixed tables
    var xor_T[256];
    var not_T[16];
    var range_T[16];
    var and_T[256];

    for (i=0; i<256; i++) xor_T[i] = xor_function(i);
    for (i=0; i<16; i++) not_T[i] = not_function(i);
    for (i=0; i<16; i++) range_T[i] = range_function(i);
    for (i=0; i<256; i++) and_T[i] = and_function(i);

    var xor_M[256];
    var not_M[16];
    var range_M[16];
    var and_M[256];

    var xor_I[32*48 + 24*64 + 16*64];
    var xor_A[32*48 + 24*64 + 16*64];

    var not_I[8*64];
    var not_A[8*64];

    var range_I[48*64];
    var range_A[48*64];

    var and_I[40*64];
    var and_A[40*64];
    
    // Update all I and A at the end

    component sigmaPlus[48];
    // 6 random tables
    // 8 lookups into each table * 48 rounds
    // + 32 lookups for xor * 48 rounds
    // + 8 lookups for range * 48 rounds
    for (i=0; i<48; i++) sigmaPlus[i] = SigmaPlus();

    component ct_k[64];
    // No tables
    for (i=0; i<64; i++) ct_k[i] = K(i);

    component t1[64];
    // 3 random tables
    // 8 lookups into each table * 64 rounds
    // + 8 + 16 lookups for xor * 64 rounds
    // + 8 lookups for not * 64 rounds
    // + 16 lookups for and * 64 rounds
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) t1[i] = T1();

    component t2[64];
    // 3 random tables
    // 8 lookups into each table * 64 rounds
    // + 24 lookups for and * 64 rounds
    // + 16 lookups for xor * 64 rounds
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) t2[i] = T2();

    component suma[64];
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) suma[i] = BinSum(32, 2);

    component sume[64];
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) sume[i] = BinSum(32, 2);

    component fsum[8];
    // + 8 lookups for range * 64 rounds
    for (i=0; i<8; i++) fsum[i] = BinSum(32, 2);

    var k;
    var t;

    for (t=0; t<64; t++) {
        if (t<16) {
            for (k=0; k<8; k++) {
                w[t][k] <== inp[t*8+7-k];
            }
        } else {
            for (k=0; k<8; k++) {
                sigmaPlus[t-16].in2[k] <== w[t-2][k];
                sigmaPlus[t-16].in7[k] <== w[t-7][k];
                sigmaPlus[t-16].in15[k] <== w[t-15][k];
                sigmaPlus[t-16].in16[k] <== w[t-16][k];
            }

            for (k=0; k<8; k++) {
                w[t][k] <== sigmaPlus[t-16].out[k];
            }
        }
    }

    for (k=0; k<8; k++ ) {
        a[0][k] <== hin[k];
        b[0][k] <== hin[8*1 + k];
        c[0][k] <== hin[8*2 + k];
        d[0][k] <== hin[8*3 + k];
        e[0][k] <== hin[8*4 + k];
        f[0][k] <== hin[8*5 + k];
        g[0][k] <== hin[8*6 + k];
        h[0][k] <== hin[8*7 + k];
    }

    for (t = 0; t<64; t++) {
        for (k=0; k<8; k++) {
            t1[t].h[k] <== h[t][k];
            t1[t].e[k] <== e[t][k];
            t1[t].f[k] <== f[t][k];
            t1[t].g[k] <== g[t][k];
            t1[t].k[k] <== ct_k[t].out[k];
            t1[t].w[k] <== w[t][k];

            t2[t].a[k] <== a[t][k];
            t2[t].b[k] <== b[t][k];
            t2[t].c[k] <== c[t][k];
        }

        for (k=0; k<8; k++) {
            sume[t].in[0][k] <== d[t][k];
            sume[t].in[1][k] <== t1[t].out[k];

            suma[t].in[0][k] <== t1[t].out[k];
            suma[t].in[1][k] <== t2[t].out[k];
        }

        for (k=0; k<8; k++) {
            h[t+1][k] <== g[t][k];
            g[t+1][k] <== f[t][k];
            f[t+1][k] <== e[t][k];
            e[t+1][k] <== sume[t].out[k];
            d[t+1][k] <== c[t][k];
            c[t+1][k] <== b[t][k];
            b[t+1][k] <== a[t][k];
            a[t+1][k] <== suma[t].out[k];
        }
    }

    for (k=0; k<8; k++) {
        fsum[0].in[0][k] <==  hin[8*0+k];
        fsum[0].in[1][k] <==  a[64][k];
        fsum[1].in[0][k] <==  hin[8*1+k];
        fsum[1].in[1][k] <==  b[64][k];
        fsum[2].in[0][k] <==  hin[8*2+k];
        fsum[2].in[1][k] <==  c[64][k];
        fsum[3].in[0][k] <==  hin[8*3+k];
        fsum[3].in[1][k] <==  d[64][k];
        fsum[4].in[0][k] <==  hin[8*4+k];
        fsum[4].in[1][k] <==  e[64][k];
        fsum[5].in[0][k] <==  hin[8*5+k];
        fsum[5].in[1][k] <==  f[64][k];
        fsum[6].in[0][k] <==  hin[8*6+k];
        fsum[6].in[1][k] <==  g[64][k];
        fsum[7].in[0][k] <==  hin[8*7+k];
        fsum[7].in[1][k] <==  h[64][k];
    }

    for (k=0; k<8; k++) {
        out[7-k]     === fsum[0].out[k];
        out[8+7-k]  === fsum[1].out[k];
        out[16+7-k]  === fsum[2].out[k];
        out[24+7-k]  === fsum[3].out[k];
        out[32+7-k] === fsum[4].out[k];
        out[40+7-k] === fsum[5].out[k];
        out[48+7-k] === fsum[6].out[k];
        out[56+7-k] === fsum[7].out[k];
    }
}
