pragma circom 2.1.0;

include "lookup.circom";
include "./sha256_lookup/random_tables.circom";

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

function multiplicity_generator(I, A, len, T) {
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

template test_lookup_single_table() {
    // x is a nibble
    signal input x;
    signal input y;
    assert(x < 16);
    assert(y < 16);

    signal output out;

    component table_t[2];
    var out_x = table_function(x, 00);
    var out_y = table_function(y, 00);

    signal val;
    table_t[0] = table_template(00);
    table_t[0].index <== x;
    val <== table_t[0].out_nibble;
    log("val", val, "x", x);
    assert(val == out_x);

    signal val2;
    table_t[1] = table_template(00);
    table_t[1].index <== y;
    val2 <== table_t[1].out_nibble;
    log("val2", val2, "y", y);
    assert(val2 == out_y);

    // lookup
    component id_lookup = indexed_lookup(2, 256);
    var A[2];
    var I[2];
    var T[256];
    var M[256];
    var alpha = 1033;

    A[0] = val;
    A[1] = val2;
    I[0] = x;
    I[1] = y;
    for (var i=0; i<256; i++) {
        T[i] = table_function(i, 00);
    }
    M = multiplicity_generator(I, A, 2, T);

    id_lookup.alpha <== alpha;
    id_lookup.A <== A;
    id_lookup.I <== I;
    id_lookup.T <== T;
    id_lookup.M <-- M;

    out <== id_lookup.out;
}

template test_lookup_multiple_table(n) {
    signal input x[n];
    signal output out;

    component table_t[n];
    var out_vals[n];
    for (var i=0; i<n; i++) {
        table_t[i] = table_template(00);
        out_vals[i] = table_function(x[i], 00);
    }

    signal vals[n];

    for (var i=0; i<n; i++) {
        table_t[i].index <== x[i];
        vals[i] <== table_t[i].out_nibble;
        log("vals[i]", vals[i], "x[i]", x[i]);
        assert(vals[i] == out_vals[i]);
    }

    // lookup
    component id_lookup = indexed_lookup(n, 256);
    var A[n];
    var I[n];
    var T[256];
    var M[256];
    var alpha = 1033;

    for (var i=0; i<n; i++) {
        A[i] = vals[i];
        I[i] = x[i];
    }
    for (var i=0; i<256; i++) {
        T[i] = table_function(i, 00);
    }
    M = multiplicity_generator(I, A, n, T);
    for (var i=0; i<256; i++) {
        log("M[",i,"]", M[i], "T[",i,"]", T[i]);
    }

    id_lookup.alpha <== alpha;
    id_lookup.A <== A;
    id_lookup.I <== I;
    id_lookup.T <== T;
    id_lookup.M <-- M;

    out <== id_lookup.out;
}

template Lookup_ssigma0() {
    signal input x;
    signal output out[5];
    assert (x < 2**32);

    signal x_nibbles[8];
    for (var i=0; i<8; i++) {
        x_nibbles[i] <-- (x >> 4*i) & 15;
    }

    // Recomposition
    var sum = 0;
    for (var i=0; i<8; i++) {
        sum += x_nibbles[i] * 16**i;
    }
    sum === x;

    component table[3][8];

    signal table_vals[3][8];

    for (var i=0; i<3; i++) {
        for (var j=0; j<8; j++) {
            table[i][j] = table_template(i);
            table[i][j].index <== x_nibbles[j];
            table_vals[i][j] <== table[i][j].out_nibble;
        }
    }

    component id_lookup[3];
    var A[3][8];
    var I[3][8];
    var T[3][256];
    var M[3][256];
    var alpha[3] = [1033, 1034, 1035];

    for (var i=0; i<3; i++) {
        id_lookup[i] = indexed_lookup(8, 256);
        I[i] = x_nibbles;
        A[i] = table_vals[i];
        for (var j=0; j<256; j++) {
            T[i][j] = table_function(j, i);
        }
        M[i] = multiplicity_generator(I[i], A[i], 8, T[i]);

        id_lookup[i].alpha <== alpha[i];

        id_lookup[i].A <== A[i];
        id_lookup[i].I <== I[i];
        id_lookup[i].T <== T[i];
        id_lookup[i].M <-- M[i];

        out[i] <== id_lookup[i].out;
    }

    // XOR
    component xor_table[2][8];

    signal xor_vals[2][8];

    for (var i=0; i<2; i++) {
        for (var j=0; j<8; j++) {
            xor_table[i][j] = xor_template();
            xor_table[i][j].index <== table_vals[i][j] * 16 + table_vals[i+1][j];
            xor_vals[i][j] <== xor_table[i][j].out_nibble;

            assert(xor_vals[i][j] == table_vals[i][j] ^ table_vals[i+1][j]);
        }
    }

    component xor_lookup[2];
    var xor_A[16];
    var xor_I[16];
    var xor_T[256];
    var xor_M[256];
    var xor_alpha = 1036;

    signal xor_out;
    component id_lookup_xor;

    for (var j=0; j<8; j++) {
        xor_I[j] = table_vals[0][j] + table_vals[1][j] * 16;
        xor_A[j] = table_vals[0][j] ^ table_vals[1][j];
        for (var i=0; i<256; i++) {
            xor_T[i] = xor_function(i);
        }

        xor_I[8+j] = table_vals[2][j] + xor_A[j] * 16;
        xor_A[8+j] = table_vals[2][j] ^ xor_A[j];
    }

    xor_M = multiplicity_generator(xor_I, xor_A, 16, xor_T);

    id_lookup_xor = indexed_lookup(16, 256);
    id_lookup_xor.alpha <== xor_alpha;
    id_lookup_xor.A <-- xor_A;
    id_lookup_xor.I <-- xor_I;
    id_lookup_xor.T <== xor_T;
    id_lookup_xor.M <-- xor_M;

    xor_out <== id_lookup_xor.out;

    // Recomposition
    var out_sum = 0;
    for (var i=0; i<8; i++) {
        out_sum += xor_A[8+i] * 16**i;
    }
    assert (out_sum == ssigma0(x));
}

template call_ssigma0() {
    signal input in[64];
    signal output out[64];

    signal x_nibbles[64 * 8];
    
    var A[3][64 * 8];
    var I[3][64 * 8];
    var T[4][256];
    var M[4][256];

    var xor_A[64 * 16];
    var xor_I[64 * 16];

    var alpha[4] = [1033, 1034, 1035, 1036];

    // Define tables
    for (var i=0; i<3; i++) {
        for (var j=0; j<256; j++) {
            T[i][j] = table_function(j, i);
        }
    }
    for (var j=0; j<256; j++) {
        T[3][j] = xor_function(j);
    }

    // Accumulation
    for (var k=0; k<64; k++) {
        for (var i=0; i<8; i++) {
            x_nibbles[k*8 + i] <-- (in[k] >> 4*i) & 15;
        }

        // Recomposition
        var sum = 0;
        for (var i=0; i<8; i++) {
            sum += x_nibbles[k*8 + i] * 16**i;
        }
        sum === in[k];

        for (var i=0; i<3; i++) {
            for (var j=0; j<8; j++) {
                A[i][k*8 + j] = table_function(x_nibbles[k*8 + j], i);
                I[i][k*8 + j] = x_nibbles[k*8 + j];
            }
        }

        // xors
        for (var j=0; j<8; j++) {
            xor_I[k*16 + j] = table_function(x_nibbles[k*8 + j], 0) + table_function(x_nibbles[k*8 + j], 1) * 16;
            xor_A[k*16 + j] = table_function(x_nibbles[k*8 + j], 0) ^ table_function(x_nibbles[k*8 + j], 1);

            xor_I[k*16 + 8 + j] = table_function(x_nibbles[k*8 + j], 2) + xor_A[k*16 + j] * 16;
            xor_A[k*16 + 8 + j] = table_function(x_nibbles[k*8 + j], 2) ^ xor_A[k*16 + j];
        }
    }    

    // Lookup
    for (var i=0; i<3; i++) {
        M[i] = multiplicity_generator(I[i], A[i], 64 * 8, T[i]);
    }
    M[3] = multiplicity_generator(xor_I, xor_A, 64 * 16, T[3]);

    component id_lookup[3];
    for (var i=0; i<3; i++) {
        id_lookup[i] = indexed_lookup(64 * 8, 256);

        id_lookup[i].alpha <== alpha[i];
        id_lookup[i].A <-- A[i];
        id_lookup[i].I <-- I[i];
        id_lookup[i].T <== T[i];
        id_lookup[i].M <-- M[i];
        out[i] <== id_lookup[i].out;
    }

    component xor_lookup = indexed_lookup(64 * 16, 256);
    xor_lookup.alpha <== alpha[3];
    xor_lookup.A <-- xor_A;
    xor_lookup.I <-- xor_I;
    xor_lookup.T <== T[3];
    xor_lookup.M <-- M[3];
    out[3] <== xor_lookup.out;

    // Recomposition
    for (var k=0; k<64; k++) {
        var out_sum = 0;
        for (var i=0; i<8; i++) {
            out_sum += xor_A[k*16 + 8 + i] * 16**i;
        }
        assert(out_sum == ssigma0(in[k]));
    }

}

component main = call_ssigma0();