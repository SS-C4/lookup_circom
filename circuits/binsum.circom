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

/*

Binary Sum
==========

This component creates a binary sum componet of ops operands and n bits each operand.

e is Number of carries: Depends on the number of operands in the input.

Main Constraint:
   in[0][0]     * 2^0  +  in[0][1]     * 2^1  + ..... + in[0][n-1]    * 2^(n-1)  +
 + in[1][0]     * 2^0  +  in[1][1]     * 2^1  + ..... + in[1][n-1]    * 2^(n-1)  +
 + ..
 + in[ops-1][0] * 2^0  +  in[ops-1][1] * 2^1  + ..... + in[ops-1][n-1] * 2^(n-1)  +
 ===
   out[0] * 2^0  + out[1] * 2^1 +   + out[n+e-1] *2(n+e-1)

To waranty binary outputs:

    out[0]     * (out[0] - 1) === 0
    out[1]     * (out[0] - 1) === 0
    .
    .
    .
    out[n+e-1] * (out[n+e-1] - 1) == 0

 */


/*
    This function calculates the number of extra bits in the output to do the full sum.
 */
 pragma circom 2.0.0;

function nbits(a) {
    var n = 1;
    var r = 0;
    while (n-1<a) {
        r++;
        n *= 2;
    }
    return r;
}


template BinSum(n, ops) {
    var nout = nbits((2**n -1)*ops);
    signal input in[ops][n];
    signal output out[nout];

    var lin = 0;
    var lout = 0;

    var k;
    var j;

    var e2;

    e2 = 1;
    for (k=0; k<n; k++) {
        for (j=0; j<ops; j++) {
            lin += in[j][k] * e2;
        }
        e2 = e2 + e2;
    }

    e2 = 1;
    for (k=0; k<nout; k++) {
        out[k] <-- (lin >> k) & 1;

        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;

        lout += out[k] * e2;

        e2 = e2+e2;
    }

    // Ensure the sum;

    lin === lout;
}

template BinSum_Lookup(ops) {
    signal input in[ops][8];
    signal output out[16];

    signal output range_I[8];
    signal output range_A[8];

    var in_int[ops];
    for (var i=0; i<ops; i++) {
        in_int[i] = 0;
        for (var j=0; j<8; j++) {
            in_int[i] += in[i][j] * (1 << 4*j);
        }
    }

    var sum = 0;
    for (var i=0; i<ops; i++) {
        sum += in_int[i];
    }

    // Get rem and quotient
    signal rem;
    rem <-- sum % (2 ** 32);
    signal quotient;
    quotient <-- sum \ (2 ** 32);

    // Constraint for sum = rem + 2^32 * quotient
    sum === rem + 2 ** 32 * quotient;

    // Decompose into nibbles
    for (var i=0; i<8; i++) {
        range_I[i] <-- (rem >> 4*i) & 15;
        range_A[i] <-- range_I[i];
    }

    // Recomposition constraint
    var rec_sum = 0;
    for (var i=0; i<8; i++) {
        rec_sum += range_A[i] * (1 << 4*i);
    }
    rec_sum === rem;

    for (var i=0; i<8; i++) {
        out[i] <-- range_A[i];
    }
    
}