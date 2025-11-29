// src/aes/aesEngine.ts

/**
 * Frontend AES helpers & types for the visualizer.
 *
 * IMPORTANT:
 *  - This file only provides:
 *      • type definitions that match backend JSON
 *      • byte/format helper functions used by the React components
 */

// =======================
//  Basic AES-related types
// =======================

export type AesBlockMode = "ECB" | "CBC" | "CFB" | "OFB" | "CTR";

/**
 * AES state as a 4x4 matrix of bytes (column-major)
 */
export type AESState = number[][]; // [4][4], but we don't enforce that at type level

export interface AESRoundStep {
  round: number;          // round number (0..Nr)
  step: string;           // e.g. "SubBytes", "ShiftRows", etc.
  state: AESState | null; // can be null if backend skips it for that step
  roundKey: AESState | null;
}

/**
 * Per-block AES result, including ciphertext bytes
 * and step-by-step matrices for visualization.
 */
export interface AESEncryptionResult {
  ciphertext: number[];        // ciphertext bytes for this block
  steps: AESRoundStep[];       // full round-by-round visualization
}

/**
 * Multi-block encryption result returned by the backend.
 * Used by AESFullText.tsx.
 */
export interface MultiBlockEncryptionBlockResult {
  blockIndex: number;          // 0-based index
  plaintextBlockHex: string;   // 32 hex chars (16 bytes) for the plaintext block
  ciphertextBlockHex: string;  // 32 hex chars for the ciphertext block
  aesResult: AESEncryptionResult;
}

export interface MultiBlockEncryptionResult {
  mode: AesBlockMode;
  blockResults: MultiBlockEncryptionBlockResult[];
  paddingDescription: string;  // e.g. "PKCS#7 padding with X bytes on last block"
  ciphertextHex: string;       // full ciphertext of all blocks concatenated
}

/**
 * Multi-block decryption result returned by the backend.
 * Used by AESFullTextDecryption.tsx.
 */
export interface MultiBlockDecryptionBlockResult {
  blockIndex: number;          // 0-based index
  ciphertextBlockHex: string;  // 32 hex chars (16 bytes)
  plaintextBlockHex: string;   // 32 hex chars after decryption (before removing padding or as needed)
  aesResult: AESEncryptionResult;
}

export interface MultiBlockDecryptionResult {
  mode: AesBlockMode;
  blockResults: MultiBlockDecryptionBlockResult[];
  paddingDescription: string;  // description of how padding was handled/removed
  plaintextHex: string;        // full plaintext hex for the entire message
}

// =======================
//  Byte / format helpers
// =======================

/**
 * Convert hex string (with or without spaces) to array of bytes.
 */
export function hexToBytes(hex: string): number[] {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length === 0) return [];

  const normalized = clean.length % 2 === 1 ? "0" + clean : clean;

  const bytes: number[] = [];
  for (let i = 0; i < normalized.length; i += 2) {
    const byteStr = normalized.slice(i, i + 2);
    const byte = parseInt(byteStr, 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hex byte: "${byteStr}"`);
    }
    bytes.push(byte);
  }
  return bytes;
}

/**
 * Convert array of bytes to hex string (no spaces, lowercase by default).
 */
export function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Convert array of bytes to a space-separated binary string.
 * Example: [0xAA, 0x01] -> "10101010 00000001"
 */
export function bytesToBinary(bytes: number[]): string {
  return bytes
    .map((b) => b.toString(2).padStart(8, "0"))
    .join(" ");
}

/**
 * Convert array of bytes to a space-separated decimal string.
 * Example: [10, 255] -> "10 255"
 */
export function bytesToDecimal(bytes: number[]): string {
  return bytes.map((b) => b.toString(10)).join(" ");
}

