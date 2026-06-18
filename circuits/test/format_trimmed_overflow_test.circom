pragma circom 2.0.0;

//
// Negative test harness for the FormatTrimmedAmount field-overflow fix.
// (docs/security/VULN-cowswap-zk-amount-overflow.md)
//
// Instantiates ONLY FormatTrimmedAmount with the CoW production
// parameters (MAX_INT_DIGITS=10, FRAC_DIGITS=4, MAX_DECIMALS=18) and
// exposes raw_amount as the public signal. This isolates the amount
// recomposition from the rest of the order circuit (Poseidon, Merkle,
// etc.) so a witness that fails here fails *specifically* on the
// raw_amount range check / recomposition — not on some unrelated hash
// mismatch.
//
// Used by docs/security/cowswap-zk-poc/run_overflow_negative_test.sh:
//   * the PoC forged witness (raw_amount ≈ 2^254) MUST fail witness
//     generation (Num2Bits(190) constraint), proving the fix bites;
//   * a benign witness (the same 0.2000 display, honest small amount)
//     MUST succeed, proving the fix is lossless for real amounts.

include "../lib/format.circom";

template FormatTrimmedOverflowTest() {
    signal input  raw_amount;
    signal input  scale_factor;
    signal input  int_digits[10];
    signal input  frac_digits[4];
    signal input  n_leading_zeros;
    signal input  remainder;
    signal input  is_sub_precision;

    signal output ok;

    component f = FormatTrimmedAmount(10, 4, 18);
    f.raw_amount <== raw_amount;
    f.scale_factor <== scale_factor;
    for (var i = 0; i < 10; i++) f.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < 4;  i++) f.frac_digits[i] <== frac_digits[i];
    f.n_leading_zeros <== n_leading_zeros;
    f.remainder <== remainder;
    f.is_sub_precision <== is_sub_precision;

    f.ok === 1;
    ok <== f.ok;
}

component main {public [raw_amount]} = FormatTrimmedOverflowTest();
