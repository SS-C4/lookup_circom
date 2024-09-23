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

function multiplicity_generator_256(I, A, len, T) {
    var M[256];
    for (var i=0; i<256; i++) {
        M[i] = 0;
    }
    for (var i=0; i<256; i++) {
        for (var j=0; j<len; j++) {
            if (I[j] == i && A[j] == T[i]) {
                M[i] += 1;
            }
        }
    }
    return M;
}

function multiplicity_generator_16(I, A, len, T) {
    var M[16];
    for (var i=0; i<16; i++) {
        M[i] = 0;
    }
    for (var i=0; i<16; i++) {
        for (var j=0; j<len; j++) {
            if (I[j] == i && A[j] == T[i]) {
                M[i] += 1;
            }
        }
    }
    return M;
}

template Sha256compression() {
    signal input hin[64];
    signal input inp[128];
    signal output out[64];
    signal output lookup_out[16];

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
    for (i=0; i<16; i++) alpha[i] = (i + 131244);

    // Random tables
    var random_T[12][256];
    for (var j=0; j<256; j++) {
        random_T[0][j] = table_function(j, 00);
        random_T[1][j] = table_function(j, 01);
        random_T[2][j] = table_function(j, 02);
        random_T[3][j] = table_function(j, 10);
        random_T[4][j] = table_function(j, 11);
        random_T[5][j] = table_function(j, 12);
        random_T[6][j] = table_function(j, 30);
        random_T[7][j] = table_function(j, 31);
        random_T[8][j] = table_function(j, 32);
        random_T[9][j] = table_function(j, 20);
        random_T[10][j] = table_function(j, 21);
        random_T[11][j] = table_function(j, 22);
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

    var xor_I[32*48 + 24*64 + 32*64];
    var xor_A[32*48 + 24*64 + 32*64];

    var not_I[8*64];
    var not_A[8*64];

    var range_I[8*48 + 32*64 + 8*8];
    var range_A[8*48 + 32*64 + 8*8];

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
    // + 16 + 16 lookups for xor * 64 rounds
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) t2[i] = T2();

    component suma[64];
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) suma[i] = BinSum_Lookup(2);

    component sume[64];
    // + 8 lookups for range * 64 rounds
    for (i=0; i<64; i++) sume[i] = BinSum_Lookup(2);

    component fsum[8];
    // + 8 lookups for range * 8 rounds
    for (i=0; i<8; i++) fsum[i] = BinSum_Lookup(2);

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

    // Update SigmaPlus I and A
    for (t=0; t<48; t++) {
        for (k=0; k<8; k++) {
            random_I_0[0][t*8+k] = sigmaPlus[t].random_I_0[0][k];
            random_I_0[1][t*8+k] = sigmaPlus[t].random_I_0[1][k];
            random_I_0[2][t*8+k] = sigmaPlus[t].random_I_0[2][k];
            random_I_0[3][t*8+k] = sigmaPlus[t].random_I_0[3][k];
            random_I_0[4][t*8+k] = sigmaPlus[t].random_I_0[4][k];
            random_I_0[5][t*8+k] = sigmaPlus[t].random_I_0[5][k];

            random_A_0[0][t*8+k] = sigmaPlus[t].random_A_0[0][k];
            random_A_0[1][t*8+k] = sigmaPlus[t].random_A_0[1][k];
            random_A_0[2][t*8+k] = sigmaPlus[t].random_A_0[2][k];
            random_A_0[3][t*8+k] = sigmaPlus[t].random_A_0[3][k];
            random_A_0[4][t*8+k] = sigmaPlus[t].random_A_0[4][k];
            random_A_0[5][t*8+k] = sigmaPlus[t].random_A_0[5][k];
        }

        for (k=0; k<32; k++) {
            xor_I[t*32+k] = sigmaPlus[t].xor_I[k];
            xor_A[t*32+k] = sigmaPlus[t].xor_A[k];
        }

        for (k=0; k<8; k++) {
            range_I[t*8+k] = sigmaPlus[t].range_I[k];
            range_A[t*8+k] = sigmaPlus[t].range_A[k];
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

        // Update T1 and T2 I and A
        for (k=0; k<8; k++) {
            random_I_1[0][t*8+k] = t1[t].random_I_1[0][k];
            random_I_1[1][t*8+k] = t1[t].random_I_1[1][k];
            random_I_1[2][t*8+k] = t1[t].random_I_1[2][k];
            random_I_1[3][t*8+k] = t2[t].random_I_1[0][k];
            random_I_1[4][t*8+k] = t2[t].random_I_1[1][k];
            random_I_1[5][t*8+k] = t2[t].random_I_1[2][k];

            random_A_1[0][t*8+k] = t1[t].random_A_1[0][k];
            random_A_1[1][t*8+k] = t1[t].random_A_1[1][k];
            random_A_1[2][t*8+k] = t1[t].random_A_1[2][k];
            random_A_1[3][t*8+k] = t2[t].random_A_1[0][k];
            random_A_1[4][t*8+k] = t2[t].random_A_1[1][k];
            random_A_1[5][t*8+k] = t2[t].random_A_1[2][k];
        }

        for (k=0; k<24; k++) {
            xor_I[32*48 + t*24 + k] = t1[t].xor_I[k];
            xor_A[32*48 + t*24 + k] = t1[t].xor_A[k];
        }
        for (k=0; k<32; k++) {
            xor_I[32*48 + 24*64 + t*32 + k] = t2[t].xor_I[k];
            xor_A[32*48 + 24*64 + t*32 + k] = t2[t].xor_A[k];
        }

        for (k=0; k<8; k++) {
            not_I[t*8+k] = t1[t].not_I[k];
            not_A[t*8+k] = t1[t].not_A[k];
        }

        for (k=0; k<16; k++) {
            and_I[t*16+k] = t1[t].and_I[k];
            and_A[t*16+k] = t1[t].and_A[k];
        }
        for (k=0; k<24; k++) {
            and_I[16*64 + t*24 + k] = t2[t].and_I[k];
            and_A[16*64 + t*24 + k] = t2[t].and_A[k];
        }

        for (k=0; k<8; k++) {
            range_I[8*48 + t*8 + k] = t1[t].range_I[k];
            range_A[8*48 + t*8 + k] = t1[t].range_A[k];
        }
        for (k=0; k<8; k++) {
            range_I[8*48 + 8*64 + t*8 + k] = t2[t].range_I[k];
            range_A[8*48 + 8*64 + t*8 + k] = t2[t].range_A[k];
        }

        for (k=0; k<8; k++) {
            sume[t].in[0][k] <== d[t][k];
            sume[t].in[1][k] <== t1[t].out[k];

            suma[t].in[0][k] <== t1[t].out[k];
            suma[t].in[1][k] <== t2[t].out[k];
        }

        // Update sume and suma I and A
        for (k=0; k<8; k++) {
            range_I[8*48 + 8*64 + 8*64 + t*8 + k] = sume[t].range_I[k];
            range_A[8*48 + 8*64 + 8*64 + t*8 + k] = sume[t].range_A[k];
        }
        for (k=0; k<8; k++) {
            range_I[8*48 + 8*64 + 8*64 + 8*64 + t*8 + k] = suma[t].range_I[k];
            range_A[8*48 + 8*64 + 8*64 + 8*64 + t*8 + k] = suma[t].range_A[k];
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

    // Update fsum I and A
    for (k=0; k<8; k++) {
        for (i=0; i<8; i++) {
            range_I[8*48 + 8*64 + 8*64 + 8*64 + 8*64 + i*8 + k] = fsum[i].range_I[k];
            range_A[8*48 + 8*64 + 8*64 + 8*64 + 8*64 + i*8 + k] = fsum[i].range_A[k];
        }
    }

    // Lookups
    // Generate M
    for (i=0; i<6; i++) {
        for (var t=0; t<256; t++) {
            random_M[i][t] = 0;
            random_M[i+6][t] = 0;
        }
        for (var t=0; t<256; t++) {
            for (var j=0; j<8*48; j++) {
                if (random_I_0[i][j] == t && random_A_0[i][j] == random_T[i][t]) {
                    random_M[i][t] += 1;
                }
            }
            for (var j=0; j<8*64; j++) {
                if (random_I_1[i][j] == t && random_A_1[i][j] == random_T[i+6][t]) {
                    random_M[i+6][t] += 1;
                }
            }
        }
    }

    // Multiplicity generation
    // XOR
    for (i=0; i<256; i++) {
        xor_M[i] = 0;
    }
    for (var i=0; i<256; i++) {
        for (var j=0; j<32*48 + 24*64 + 32*64; j++) {
            if (xor_I[j] == i && xor_A[j] == xor_T[i]) {
                xor_M[i] += 1;
            }
        }
    }

    // NOT
    for (i=0; i<16; i++) {
        not_M[i] = 0;
    }
    for (var i=0; i<16; i++) {
        for (var j=0; j< 8*64; j++) {
            if (not_I[j] == i && not_A[j] == not_T[i]) {
                not_M[i] += 1;
            }
        }
    }

    // Range
    for (i=0; i<16; i++) {
        range_M[i] = 0;
    }
    for (var i=0; i<16; i++) {
        for (var j=0; j< 8*48 + 8*64 + 8*64 + 8*64 + 8*64 + 8*8; j++) {
            if (range_I[j] == i && range_A[j] == range_T[i]) {
                range_M[i] += 1;
            }
        }
    }

    // AND
    for (i=0; i<256; i++) {
        and_M[i] = 0;
    }
    for (var i=0; i<256; i++) {
        for (var j=0; j<40*64; j++) {
            if (and_I[j] == i && and_A[j] == and_T[i]) {
                and_M[i] += 1;
            }
        }
    }

    // Lookups
    component id_lookup[6];
    for (i=0; i<6; i++) {
        id_lookup[i] = indexed_lookup(8 * 48, 256);

        id_lookup[i].alpha <== alpha[i];
        id_lookup[i].A <-- random_A_0[i];
        id_lookup[i].I <-- random_I_0[i];
        id_lookup[i].T <== random_T[i];
        id_lookup[i].M <-- random_M[i];
        lookup_out[i] <== id_lookup[i].out;
    }

    component id_lookup1[6];
    for (i=0; i<6; i++) {
        id_lookup1[i] = indexed_lookup(8 * 64, 256);

        id_lookup1[i].alpha <== alpha[i+6];
        id_lookup1[i].A <-- random_A_1[i];
        id_lookup1[i].I <-- random_I_1[i];
        id_lookup1[i].T <== random_T[i+6];
        id_lookup1[i].M <-- random_M[i+6];
        lookup_out[i+6] <== id_lookup1[i].out;
    }

    component xor_lookup = indexed_lookup(32*48 + 24*64 + 32*64, 256);
    xor_lookup.alpha <== alpha[12];
    xor_lookup.A <-- xor_A;
    xor_lookup.I <-- xor_I;
    xor_lookup.T <== xor_T;
    xor_lookup.M <-- xor_M;
    lookup_out[12] <== xor_lookup.out;

    component not_lookup = indexed_lookup(8*64, 16);
    not_lookup.alpha <== alpha[13];
    not_lookup.A <-- not_A;
    not_lookup.I <-- not_I;
    not_lookup.T <== not_T;
    not_lookup.M <-- not_M;
    lookup_out[13] <== not_lookup.out;

    component range_lookup = indexed_lookup(8*48 + 8*64 + 8*64 + 8*64 + 8*64 + 8*8, 16);
    range_lookup.alpha <== alpha[14];
    range_lookup.A <-- range_A;
    range_lookup.I <-- range_I;
    range_lookup.T <== range_T;
    range_lookup.M <-- range_M;
    lookup_out[14] <== range_lookup.out;

    component and_lookup = indexed_lookup(40*64, 256);
    and_lookup.alpha <== alpha[15];
    and_lookup.A <-- and_A;
    and_lookup.I <-- and_I;
    and_lookup.T <== and_T;
    and_lookup.M <-- and_M;
    lookup_out[15] <== and_lookup.out;

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
