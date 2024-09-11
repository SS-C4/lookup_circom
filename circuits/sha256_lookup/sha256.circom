pragma circom 2.0.0;

include "constants.circom";
include "sha256compression.circom";

template Sha256(nNibbles) {
    signal input in[nNibbles];
    signal output out[64];

    var i;
    var k;
    var nBlocks;
    var nibblesLastBlock;


    nBlocks = ((nNibbles * 4 + 64)\512)+1;

    signal paddedIn[nBlocks*128];

    for (k=0; k<nNibbles; k++) {
        paddedIn[k] <== in[k];
    }
    // paddedIn[nNibbles] <== 1;

    for (k=nNibbles; k<nBlocks*128-16; k++) {
        paddedIn[k] <== 0;
    }

    for (k = 0; k< 16; k++) {
        paddedIn[nBlocks*128 - k -1] <== (nNibbles >> 4*k) & 15;
    }

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[nBlocks];

    for (i=0; i<nBlocks; i++) {

        sha256compression[i] = Sha256compression() ;

        if (i==0) {
            for (k=0; k<8; k++ ) {
                sha256compression[i].hin[0*8+k] <== ha0.out[k];
                sha256compression[i].hin[1*8+k] <== hb0.out[k];
                sha256compression[i].hin[2*8+k] <== hc0.out[k];
                sha256compression[i].hin[3*8+k] <== hd0.out[k];
                sha256compression[i].hin[4*8+k] <== he0.out[k];
                sha256compression[i].hin[5*8+k] <== hf0.out[k];
                sha256compression[i].hin[6*8+k] <== hg0.out[k];
                sha256compression[i].hin[7*8+k] <== hh0.out[k];
            }
        } else {
            for (k=0; k<8; k++ ) {
                sha256compression[i].hin[8*0+k] <== sha256compression[i-1].out[8*0+7-k];
                sha256compression[i].hin[8*1+k] <== sha256compression[i-1].out[8*1+7-k];
                sha256compression[i].hin[8*2+k] <== sha256compression[i-1].out[8*2+7-k];
                sha256compression[i].hin[8*3+k] <== sha256compression[i-1].out[8*3+7-k];
                sha256compression[i].hin[8*4+k] <== sha256compression[i-1].out[8*4+7-k];
                sha256compression[i].hin[8*5+k] <== sha256compression[i-1].out[8*5+7-k];
                sha256compression[i].hin[8*6+k] <== sha256compression[i-1].out[8*6+7-k];
                sha256compression[i].hin[8*7+k] <== sha256compression[i-1].out[8*7+7-k];
            }
        }

        for (k=0; k<128; k++) {
            sha256compression[i].inp[k] <== paddedIn[i*128+k];
        }
    }

    for (k=0; k<64; k++) {
        out[k] <== sha256compression[nBlocks-1].out[k];
    }

}
