pragma circom 2.1.0;

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

template ArraySum(n) {
    // Define array signals
    signal input array[n];
    signal output sum;

    // Create signals for intermediate sums
    signal sum_temp[n+1];

    // Initialize the first element of sum_temp to 0
    sum_temp[0] <== 0;

    // Create constraints to accumulate the sum
    for (var i = 0; i < n; i++) {
        sum_temp[i+1] <== sum_temp[i] + array[i];
    }

    // Output the final sum
    sum <== sum_temp[n];
}

// LogUps
template logup(a_size, tm_size) {
    signal input alpha;
    signal input A[a_size];
    signal input T[tm_size];
    signal input M[tm_size];

    signal output out;

    // Compute the sum 1/(A[i] + alpha)
    signal inva[a_size];
    component as = ArraySum(a_size);

    for (var i = 0; i < a_size; i++) {
        inva[i] <-- 1/(A[i] + alpha);
        inva[i] * (A[i] + alpha) === 1;
        as.array[i] <== inva[i];
    }

    // Compute the sum M[i]/(T[i] + alpha)
    signal invt[tm_size];
    component ts = ArraySum(tm_size);

    for (var i = 0; i < tm_size; i++) {
        invt[i] <-- 1/(T[i] + alpha);
        invt[i] * (T[i] + alpha) === 1;
        ts.array[i] <== invt[i] * M[i];
    }

    // Compare the two sums
    component isz = IsZero();
    isz.in <== as.sum - ts.sum;
    isz.out ==> out;
}

// Wrapper with index
template indexed_lookup(ai_size, tm_size) {
    signal input alpha;
    signal input A[ai_size];
    signal input I[ai_size];
    signal input T[tm_size];
    signal input M[tm_size];

    signal output out;

    // Compute AI
    signal AI[ai_size];
    for (var i = 0; i < ai_size; i++) {
        AI[i] <== A[i] * tm_size + I[i];
    }

    // Compute TM
    signal TM[tm_size];
    for (var i = 0; i < tm_size; i++) {
        TM[i] <== T[i] * tm_size + i;
    }

    component logup = logup(ai_size, tm_size);
    logup.alpha <== alpha;
    logup.A <== AI;
    logup.T <== TM;
    logup.M <== M;

    logup.out ==> out;
    assert(out == 1); // If indexed lookup is successful, output should be 1
}

// Append element and index to A and I (no checks)
template accumulate(asize) {
    signal input a;
    signal input A[asize];
    signal input i;
    signal input I[asize];

    signal output newA[asize+1];
    signal output newI[asize+1];

    for (var j = 0; j < asize; j++) {
        newA[j] <== A[j];
        newI[j] <== I[j];
    }
    newA[asize] <== a;
    newI[asize] <== i;
}

component main = indexed_lookup(2, 4);