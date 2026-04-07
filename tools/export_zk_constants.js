#!/usr/bin/env node
/**
 * export_zk_constants.js
 *
 * Reads Poseidon parameters (round constants + MDS) from the poseidon-bls12381
 * npm package and the Groth16 verification key from ZKlarity, then generates
 * Rust source files for the PQSigner_OS secure world.
 *
 * Usage: node tools/export_zk_constants.js <path-to-zklarity>
 */

const fs = require("fs");
const path = require("path");

const ZKLARITY = process.argv[2] || path.join(__dirname, "../../ZKlarity");

// BLS12-381 scalar field prime
const PRIME = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// BLS12-381 base field prime (Fp)
const FP_PRIME = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;

// ── Helpers ────────────────────────────────────────────────────────────

/** bigint → 32-byte little-endian hex array for bls12_381::Scalar::from_bytes */
function scalarToLE32(n) {
  n = ((n % PRIME) + PRIME) % PRIME;
  const bytes = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  return bytes;
}

/** bigint → 48-byte big-endian hex array for Fp */
function fpToBE48(n) {
  n = ((n % FP_PRIME) + FP_PRIME) % FP_PRIME;
  const bytes = new Array(48).fill(0);
  for (let i = 47; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

/** Format byte array as Rust array literal */
function rustBytes(bytes) {
  const hex = bytes.map(b => "0x" + b.toString(16).padStart(2, "0"));
  // Split into rows of 12
  const rows = [];
  for (let i = 0; i < hex.length; i += 12) {
    rows.push("    " + hex.slice(i, i + 12).join(", "));
  }
  return rows.join(",\n");
}

// ── Extract Poseidon constants from TS source ─────────────────────────

function extractPoseidonConstants(tsFile) {
  const src = fs.readFileSync(tsFile, "utf8");

  // Extract ROUND_CONSTANTS array
  const rcMatch = src.match(/const ROUND_CONSTANTS\s*=\s*\[([\s\S]*?)\];/);
  if (!rcMatch) throw new Error("ROUND_CONSTANTS not found in " + tsFile);
  const rcStr = rcMatch[1];
  const rcValues = [...rcStr.matchAll(/0x[0-9a-fA-F]+n/g)].map(m => BigInt(m[0].slice(0, -1)));

  // Extract MDS_MATRIX array
  const mdsMatch = src.match(/const MDS_MATRIX\s*=\s*\[([\s\S]*?)\];\s*\n\s*export/);
  if (!mdsMatch) throw new Error("MDS_MATRIX not found in " + tsFile);
  return extractMDS(mdsMatch[1], rcValues);
}

function extractMDS(mdsStr, rcValues) {
  // Parse nested array of bigints
  const rows = [];
  const rowMatches = [...mdsStr.matchAll(/\[([\s\S]*?)\]/g)];
  for (const rm of rowMatches) {
    const vals = [...rm[1].matchAll(/0x[0-9a-fA-F]+n/g)].map(m => BigInt(m[0].slice(0, -1)));
    if (vals.length > 0) rows.push(vals);
  }
  return { rc: rcValues, mds: rows };
}

// ── Extract RF/RP from TS source ──────────────────────────────────────

function extractRounds(tsFile) {
  const src = fs.readFileSync(tsFile, "utf8");
  const rfMatch = src.match(/(\d+),\s*\/\/\s*rFull|poseidonPermutation\(inputs,\s*(\d+)/);
  // Look for the poseidonPermutation call
  const callMatch = src.match(/poseidonPermutation\(inputs,\s*(\d+),\s*(\d+)/);
  if (!callMatch) throw new Error("Cannot find RF/RP in " + tsFile);
  return { rFull: parseInt(callMatch[1]), rPartial: parseInt(callMatch[2]) };
}

// ── Generate Rust source for Poseidon constants ───────────────────────

function generatePoseidonRust(name, t, rFull, rPartial, rc, mds) {
  const totalRounds = rFull + rPartial;
  const totalConstants = rc.length;
  const lines = [];

  lines.push(`/// Poseidon constants for t=${t} (${t-1} inputs), RF=${rFull}, RP=${rPartial}`);
  lines.push(`/// Generated from poseidon-bls12381 npm package`);
  lines.push(`pub mod ${name} {`);
  lines.push(`    use super::ScalarBytes;`);
  lines.push(``);
  lines.push(`    pub const T: usize = ${t};`);
  lines.push(`    pub const RF: usize = ${rFull};`);
  lines.push(`    pub const RP: usize = ${rPartial};`);
  lines.push(`    pub const N_CONSTANTS: usize = ${totalConstants};`);
  lines.push(``);

  // Round constants as [u8; 32] arrays (little-endian for Scalar::from_bytes)
  lines.push(`    pub static RC: [ScalarBytes; ${totalConstants}] = [`);
  for (let i = 0; i < rc.length; i++) {
    const le = scalarToLE32(rc[i]);
    lines.push(`        [${le.map(b => "0x" + b.toString(16).padStart(2, "0")).join(", ")}],`);
  }
  lines.push(`    ];`);
  lines.push(``);

  // MDS matrix as [t][t] array
  lines.push(`    pub static MDS: [[ScalarBytes; ${t}]; ${t}] = [`);
  for (let i = 0; i < t; i++) {
    lines.push(`        [`);
    for (let j = 0; j < t; j++) {
      const le = scalarToLE32(mds[i][j]);
      lines.push(`            [${le.map(b => "0x" + b.toString(16).padStart(2, "0")).join(", ")}],`);
    }
    lines.push(`        ],`);
  }
  lines.push(`    ];`);

  lines.push(`}`);
  return lines.join("\n");
}

// ── Generate Rust source for verification key ─────────────────────────

function generateVkRust(vk) {
  const lines = [];

  lines.push(`/// Groth16 verification key for ZKlarity clear signing circuit`);
  lines.push(`/// Generated from ZKlarity keys/verification_key.json`);
  lines.push(`/// Curve: BLS12-381, 2 public signals (H_tx, H_str)`);
  lines.push(``);

  // Helper to convert a decimal string G1 point [x, y, z] to 96-byte uncompressed
  function g1Bytes(point) {
    const x = BigInt(point[0]);
    const y = BigInt(point[1]);
    // z should be 1 (affine)
    return [...fpToBE48(x), ...fpToBE48(y)];
  }

  // Helper to convert a G2 point [[x0,x1],[y0,y1],[z0,z1]] to 192-byte uncompressed
  // bls12_381 expects: x.c1(48) || x.c0(48) || y.c1(48) || y.c0(48)
  function g2Bytes(point) {
    const x0 = BigInt(point[0][0]); // c0
    const x1 = BigInt(point[0][1]); // c1
    const y0 = BigInt(point[1][0]); // c0
    const y1 = BigInt(point[1][1]); // c1
    return [...fpToBE48(x1), ...fpToBE48(x0), ...fpToBE48(y1), ...fpToBE48(y0)];
  }

  // vk_alpha_1 (G1)
  const alpha = g1Bytes(vk.vk_alpha_1);
  lines.push(`pub static VK_ALPHA_G1: [u8; 96] = [`);
  lines.push(rustBytes(alpha));
  lines.push(`];`);
  lines.push(``);

  // vk_beta_2 (G2)
  const beta = g2Bytes(vk.vk_beta_2);
  lines.push(`pub static VK_BETA_G2: [u8; 192] = [`);
  lines.push(rustBytes(beta));
  lines.push(`];`);
  lines.push(``);

  // vk_gamma_2 (G2)
  const gamma = g2Bytes(vk.vk_gamma_2);
  lines.push(`pub static VK_GAMMA_G2: [u8; 192] = [`);
  lines.push(rustBytes(gamma));
  lines.push(`];`);
  lines.push(``);

  // vk_delta_2 (G2)
  const delta = g2Bytes(vk.vk_delta_2);
  lines.push(`pub static VK_DELTA_G2: [u8; 192] = [`);
  lines.push(rustBytes(delta));
  lines.push(`];`);
  lines.push(``);

  // IC points (G1) — IC[0], IC[1], IC[2] for 2 public signals
  lines.push(`/// IC points: IC[0] + pub[0]*IC[1] + pub[1]*IC[2]`);
  lines.push(`pub static VK_IC: [[u8; 96]; 3] = [`);
  for (let i = 0; i < vk.IC.length; i++) {
    const ic = g1Bytes(vk.IC[i]);
    lines.push(`    [`);
    lines.push(rustBytes(ic));
    lines.push(`    ],`);
  }
  lines.push(`];`);

  return lines.join("\n");
}

// ── Generate test vector ──────────────────────────────────────────────

async function generateTestVectors() {
  // Use the poseidon-bls12381 library to compute known hashes
  const poseidon = require(path.join(ZKLARITY, "node_modules/poseidon-bls12381"));

  // Test vector: supply calldata from ZKlarity
  const supplyCalldata = "617ba037" +
    "000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" +
    "000000000000000000000000000000000000000000000000000000003B9ACA00" +
    "000000000000000000000000742d35Cc6634C0532925a3b844Bc454e4438f44e" +
    "0000000000000000000000000000000000000000000000000000000000000000";

  const rawBytes = new Uint8Array(supplyCalldata.match(/.{2}/g).map(b => parseInt(b, 16)));

  // Pad to 164 bytes
  const MAX_CALLDATA = 164;
  const padded = new Uint8Array(MAX_CALLDATA);
  padded.set(rawBytes);

  // Pack into 31-byte blocks → field elements
  const N_BLOCKS_TX = Math.ceil(MAX_CALLDATA / 31); // 6
  const txFields = [];
  for (let b = 0; b < N_BLOCKS_TX; b++) {
    let acc = 0n;
    for (let i = 0; i < 31; i++) {
      const idx = b * 31 + i;
      acc = acc * 256n + BigInt(idx < MAX_CALLDATA ? padded[idx] : 0);
    }
    txFields.push(acc);
  }

  const H_tx = poseidon.poseidon6(txFields);

  // Test readable string
  const readableStr = "Supply 0000001000.000000000000000000 USDC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  const STRING_LEN = 64;
  const readableBytes = new Uint8Array(STRING_LEN);
  for (let i = 0; i < STRING_LEN && i < readableStr.length; i++) {
    readableBytes[i] = readableStr.charCodeAt(i);
  }

  const N_BLOCKS_STR = Math.ceil(STRING_LEN / 31); // 3
  const strFields = [];
  for (let b = 0; b < N_BLOCKS_STR; b++) {
    let acc = 0n;
    for (let i = 0; i < 31; i++) {
      const idx = b * 31 + i;
      acc = acc * 256n + BigInt(idx < STRING_LEN ? readableBytes[idx] : 0);
    }
    strFields.push(acc);
  }

  const H_str = poseidon.poseidon3(strFields);

  return { H_tx, H_str, txFields, strFields, padded: Array.from(padded), readableBytes: Array.from(readableBytes) };
}

// ── Generate proof test vector ────────────────────────────────────────

function generateProofTestVector() {
  const proof = JSON.parse(fs.readFileSync(path.join(ZKLARITY, "proof_supply.json"), "utf8"));
  const pub_signals = JSON.parse(fs.readFileSync(path.join(ZKLARITY, "public_supply.json"), "utf8"));

  const lines = [];

  // proof.pi_a (G1)
  const pi_a_x = BigInt(proof.pi_a[0]);
  const pi_a_y = BigInt(proof.pi_a[1]);
  const pi_a_bytes = [...fpToBE48(pi_a_x), ...fpToBE48(pi_a_y)];
  lines.push(`pub static TEST_PROOF_A: [u8; 96] = [`);
  lines.push(rustBytes(pi_a_bytes));
  lines.push(`];`);
  lines.push(``);

  // proof.pi_b (G2) — [[x0,x1],[y0,y1],[1,0]]
  // bls12_381 uncompressed: x.c1 || x.c0 || y.c1 || y.c0
  const pi_b_x0 = BigInt(proof.pi_b[0][0]);
  const pi_b_x1 = BigInt(proof.pi_b[0][1]);
  const pi_b_y0 = BigInt(proof.pi_b[1][0]);
  const pi_b_y1 = BigInt(proof.pi_b[1][1]);
  const pi_b_bytes = [...fpToBE48(pi_b_x1), ...fpToBE48(pi_b_x0), ...fpToBE48(pi_b_y1), ...fpToBE48(pi_b_y0)];
  lines.push(`pub static TEST_PROOF_B: [u8; 192] = [`);
  lines.push(rustBytes(pi_b_bytes));
  lines.push(`];`);
  lines.push(``);

  // proof.pi_c (G1)
  const pi_c_x = BigInt(proof.pi_c[0]);
  const pi_c_y = BigInt(proof.pi_c[1]);
  const pi_c_bytes = [...fpToBE48(pi_c_x), ...fpToBE48(pi_c_y)];
  lines.push(`pub static TEST_PROOF_C: [u8; 96] = [`);
  lines.push(rustBytes(pi_c_bytes));
  lines.push(`];`);
  lines.push(``);

  // Public signals as 32-byte LE Scalar bytes
  const h_tx = BigInt(pub_signals[0]);
  const h_str = BigInt(pub_signals[1]);
  const h_tx_le = scalarToLE32(h_tx);
  const h_str_le = scalarToLE32(h_str);
  lines.push(`pub static TEST_H_TX: [u8; 32] = [`);
  lines.push(`    ${h_tx_le.map(b => "0x" + b.toString(16).padStart(2, "0")).join(", ")}`);
  lines.push(`];`);
  lines.push(``);
  lines.push(`pub static TEST_H_STR: [u8; 32] = [`);
  lines.push(`    ${h_str_le.map(b => "0x" + b.toString(16).padStart(2, "0")).join(", ")}`);
  lines.push(`];`);

  return lines.join("\n");
}

// ── Main ──────────────────────────────────────────────────────────────

async function main() {
  const poseidonDir = path.join(ZKLARITY, "node_modules/poseidon-bls12381/src");

  console.log("Reading Poseidon constants...");

  // poseidon3 (t=4, for 3 inputs — used for PoseidonBytes(64))
  const p3 = extractPoseidonConstants(path.join(poseidonDir, "instances/poseidon3.ts"));
  const r3 = extractRounds(path.join(poseidonDir, "instances/poseidon3.ts"));

  // poseidon6 (t=7, for 6 inputs — used for PoseidonBytes(164))
  const p6 = extractPoseidonConstants(path.join(poseidonDir, "instances/poseidon6.ts"));
  const r6 = extractRounds(path.join(poseidonDir, "instances/poseidon6.ts"));

  console.log(`  poseidon3: t=4, RF=${r3.rFull}, RP=${r3.rPartial}, ${p3.rc.length} constants, ${p3.mds.length}x${p3.mds[0].length} MDS`);
  console.log(`  poseidon6: t=7, RF=${r6.rFull}, RP=${r6.rPartial}, ${p6.rc.length} constants, ${p6.mds.length}x${p6.mds[0].length} MDS`);

  // Generate Poseidon constants Rust file
  let poseidonRust = `//! Auto-generated Poseidon constants for BLS12-381 scalar field.
//! Generated by tools/export_zk_constants.js — DO NOT EDIT.
//!
//! Source: poseidon-bls12381 npm package (HadeHash parameters)
//! Parameters: sage generate_params_poseidon.sage 1 0 255 t 5 128 <prime>

/// 32-byte little-endian representation of a BLS12-381 scalar field element.
pub type ScalarBytes = [u8; 32];

${generatePoseidonRust("poseidon3", 4, r3.rFull, r3.rPartial, p3.rc, p3.mds)}

${generatePoseidonRust("poseidon6", 7, r6.rFull, r6.rPartial, p6.rc, p6.mds)}
`;

  const outDir = path.join(__dirname, "../secure/src/zk");
  fs.mkdirSync(outDir, { recursive: true });

  fs.writeFileSync(path.join(outDir, "poseidon_constants.rs"), poseidonRust);
  console.log(`  → secure/src/zk/poseidon_constants.rs (${(poseidonRust.length / 1024).toFixed(1)} KB)`);

  // Generate VK Rust file
  console.log("\nReading verification key...");
  const vk = JSON.parse(fs.readFileSync(path.join(ZKLARITY, "keys/verification_key.json"), "utf8"));
  const vkRust = `//! Auto-generated Groth16 verification key for ZKlarity clear signing.
//! Generated by tools/export_zk_constants.js — DO NOT EDIT.
//!
//! Source: ZKlarity keys/verification_key.json
//! Circuit: ClearSigningProof (Aave v3, 4 actions)
//! Curve: BLS12-381, Groth16, 2 public signals

${generateVkRust(vk)}
`;

  fs.writeFileSync(path.join(outDir, "vk_data.rs"), vkRust);
  console.log(`  → secure/src/zk/vk_data.rs (${(vkRust.length / 1024).toFixed(1)} KB)`);

  // Generate test vectors
  console.log("\nGenerating test vectors...");
  const tv = await generateTestVectors();
  const proofTv = generateProofTestVector();

  // Calldata bytes for test
  const calldataRust = rustBytes(tv.padded);
  const readableRust = rustBytes(tv.readableBytes);

  const tvRust = `//! Auto-generated test vectors for ZK clear signing verification.
//! Generated by tools/export_zk_constants.js — DO NOT EDIT.
//!
//! Source: ZKlarity proof_supply.json + public_supply.json

/// Supply 1000 USDC — calldata padded to 164 bytes
pub static TEST_CALLDATA: [u8; 164] = [
${calldataRust}
];

/// "Supply 0000001000.000000000000000000 USDC" (64 bytes null-padded)
pub static TEST_READABLE: [u8; 64] = [
${readableRust}
];

${proofTv}
`;

  fs.writeFileSync(path.join(outDir, "test_vectors.rs"), tvRust);
  console.log(`  → secure/src/zk/test_vectors.rs (${(tvRust.length / 1024).toFixed(1)} KB)`);

  console.log("\nDone!");
}

main().catch(e => { console.error(e); process.exit(1); });
