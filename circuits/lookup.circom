pragma circom 2.0.0;

template logup() {
    signal input alpha;
    signal output beta;

    beta <== alpha;
}

component main = logup();