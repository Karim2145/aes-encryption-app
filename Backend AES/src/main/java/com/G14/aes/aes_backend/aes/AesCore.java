package com.G14.aes.aes_backend.aes;

import com.G14.aes.aes_backend.dto.AESRoundStepDto;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure AES block cipher (128/192/256) with full round-by-round trace.
 *
 * Internal state is 4x4 row-major: state[row][col].
 * For the frontend we convert to [col][row].
 */

public class AesCore {

    // ========= PUBLIC TYPES =========

    public static class AesBlockTrace {
        private final byte[] output;
        private final List<AESRoundStepDto> steps;

        public AesBlockTrace(byte[] output, List<AESRoundStepDto> steps) {
            this.output = output;
            this.steps = steps;
        }

        public byte[] getOutput() {
            return output;
        }

        public List<AESRoundStepDto> getSteps() {
            return steps;
        }
    }

    // ========= CONSTANT TABLES (S-box, Inverse S-box, Rcon) =========

    private static final int[] S_BOX = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    private static final int[] INV_S_BOX = {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    private static final int[] RCON = {
            0x00000000,
            0x01000000,0x02000000,0x04000000,0x08000000,
            0x10000000,0x20000000,0x40000000,0x80000000,
            0x1b000000,0x36000000,
            0x6c000000,0xd8000000,0xab000000,0x4d000000,0x9a000000
    };

    // ========= PUBLIC API =========

    public static AesBlockTrace encryptBlockWithTrace(byte[] block, byte[] key) {
        if (block.length != 16) {
            throw new IllegalArgumentException("AES block must be 16 bytes.");
        }
        int Nk = key.length / 4;
        int Nr = getNr(Nk);
        int[] w = keyExpansion(key, Nk, Nr);

        int[][] state = bytesToState(block);
        List<AESRoundStepDto> steps = new ArrayList<>();

        // Round 0: initial AddRoundKey
        addRoundKey(state, w, 0);
        steps.add(makeStep(0, "Round 0 - AddRoundKey (initial)", state, roundKeyMatrix(w, 0)));

        // Rounds 1..Nr-1
        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            steps.add(makeStep(round, "Round " + round + " - SubBytes", state, roundKeyMatrix(w, round)));

            shiftRows(state);
            steps.add(makeStep(round, "Round " + round + " - ShiftRows", state, roundKeyMatrix(w, round)));

            mixColumns(state);
            steps.add(makeStep(round, "Round " + round + " - MixColumns", state, roundKeyMatrix(w, round)));

            addRoundKey(state, w, round);
            steps.add(makeStep(round, "Round " + round + " - AddRoundKey", state, roundKeyMatrix(w, round)));
        }

        // Final round (no MixColumns)
        subBytes(state);
        steps.add(makeStep(Nr, "Round " + Nr + " - SubBytes (final)", state, roundKeyMatrix(w, Nr)));

        shiftRows(state);
        steps.add(makeStep(Nr, "Round " + Nr + " - ShiftRows (final)", state, roundKeyMatrix(w, Nr)));

        addRoundKey(state, w, Nr);
        steps.add(makeStep(Nr, "Round " + Nr + " - AddRoundKey (final)", state, roundKeyMatrix(w, Nr)));

        byte[] output = stateToBytes(state);
        return new AesBlockTrace(output, steps);
    }

    public static AesBlockTrace decryptBlockWithTrace(byte[] block, byte[] key) {
        if (block.length != 16) {
            throw new IllegalArgumentException("AES block must be 16 bytes.");
        }
        int Nk = key.length / 4;
        int Nr = getNr(Nk);
        int[] w = keyExpansion(key, Nk, Nr);

        int[][] state = bytesToState(block);
        List<AESRoundStepDto> steps = new ArrayList<>();

        // Initial AddRoundKey with last round key
        addRoundKey(state, w, Nr);
        steps.add(makeStep(Nr, "Round " + Nr + " - AddRoundKey (initial dec)", state, roundKeyMatrix(w, Nr)));

        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            steps.add(makeStep(round, "Round " + round + " - InvShiftRows", state, roundKeyMatrix(w, round)));

            invSubBytes(state);
            steps.add(makeStep(round, "Round " + round + " - InvSubBytes", state, roundKeyMatrix(w, round)));

            addRoundKey(state, w, round);
            steps.add(makeStep(round, "Round " + round + " - AddRoundKey (dec)", state, roundKeyMatrix(w, round)));

            invMixColumns(state);
            steps.add(makeStep(round, "Round " + round + " - InvMixColumns", state, roundKeyMatrix(w, round)));
        }

        invShiftRows(state);
        steps.add(makeStep(0, "Round 0 - InvShiftRows (final)", state, roundKeyMatrix(w, 0)));

        invSubBytes(state);
        steps.add(makeStep(0, "Round 0 - InvSubBytes (final)", state, roundKeyMatrix(w, 0)));

        addRoundKey(state, w, 0);
        steps.add(makeStep(0, "Round 0 - AddRoundKey (final dec)", state, roundKeyMatrix(w, 0)));

        byte[] output = stateToBytes(state);
        return new AesBlockTrace(output, steps);
    }

    // ========= INTERNAL UTILS =========

    private static int getNr(int Nk) {
        return switch (Nk) {
            case 4 -> 10; // 128-bit
            case 6 -> 12; // 192-bit
            case 8 -> 14; // 256-bit
            default -> throw new IllegalArgumentException("Unsupported Nk: " + Nk);
        };
    }

    private static int[] keyExpansion(byte[] key, int Nk, int Nr) {
        int Nb = 4;
        int[] w = new int[Nb * (Nr + 1)];

        // initial key words
        for (int i = 0; i < Nk; i++) {
            w[i] = ((key[4 * i] & 0xFF) << 24)
                    | ((key[4 * i + 1] & 0xFF) << 16)
                    | ((key[4 * i + 2] & 0xFF) << 8)
                    | (key[4 * i + 3] & 0xFF);
        }

        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            int temp = w[i - 1];
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ RCON[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
        }
        return w;
    }

    private static int subWord(int w) {
        return ((S_BOX[(w >> 24) & 0xFF] << 24)
                | (S_BOX[(w >> 16) & 0xFF] << 16)
                | (S_BOX[(w >> 8) & 0xFF] << 8)
                | (S_BOX[w & 0xFF]));
    }

    private static int rotWord(int w) {
        return ((w << 8) & 0xFFFFFFFF) | ((w >>> 24) & 0xFF);
    }

    private static int[][] bytesToState(byte[] block) {
        int[][] state = new int[4][4]; // [row][col]
        for (int i = 0; i < 16; i++) {
            int col = i / 4;
            int row = i % 4;
            state[row][col] = block[i] & 0xFF;
        }
        return state;
    }

    private static byte[] stateToBytes(int[][] state) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int col = i / 4;
            int row = i % 4;
            out[i] = (byte) (state[row][col] & 0xFF);
        }
        return out;
    }

    private static void addRoundKey(int[][] state, int[] w, int round) {
        byte[] keyBytes = new byte[16];
        for (int c = 0; c < 4; c++) {
            int word = w[round * 4 + c];
            keyBytes[4 * c]     = (byte) ((word >> 24) & 0xFF);
            keyBytes[4 * c + 1] = (byte) ((word >> 16) & 0xFF);
            keyBytes[4 * c + 2] = (byte) ((word >> 8) & 0xFF);
            keyBytes[4 * c + 3] = (byte) (word & 0xFF);
        }
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] ^= (keyBytes[c * 4 + r] & 0xFF);
            }
        }
    }

    private static void subBytes(int[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = S_BOX[state[r][c]];
            }
        }
    }

    private static void invSubBytes(int[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = INV_S_BOX[state[r][c]];
            }
        }
    }

    private static void shiftRows(int[][] state) {
        // row 0 unchanged
        state[1] = rotateLeft(state[1], 1);
        state[2] = rotateLeft(state[2], 2);
        state[3] = rotateLeft(state[3], 3);
    }

    private static void invShiftRows(int[][] state) {
        state[1] = rotateRight(state[1], 1);
        state[2] = rotateRight(state[2], 2);
        state[3] = rotateRight(state[3], 3);
    }

    private static int[] rotateLeft(int[] row, int count) {
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            out[i] = row[(i + count) % 4];
        }
        return out;
    }

    private static int[] rotateRight(int[] row, int count) {
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            out[i] = row[(i - count + 4) % 4];
        }
        return out;
    }

    private static void mixColumns(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int[] col = new int[4];
            for (int r = 0; r < 4; r++) {
                col[r] = state[r][c];
            }
            int[] mixed = mixSingleColumn(col);
            for (int r = 0; r < 4; r++) {
                state[r][c] = mixed[r];
            }
        }
    }

    private static void invMixColumns(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int[] col = new int[4];
            for (int r = 0; r < 4; r++) {
                col[r] = state[r][c];
            }
            int[] mixed = invMixSingleColumn(col);
            for (int r = 0; r < 4; r++) {
                state[r][c] = mixed[r];
            }
        }
    }

    private static int xtime(int a) {
        return ((a & 0x80) != 0) ? (((a << 1) ^ 0x1B) & 0xFF) : ((a << 1) & 0xFF);
    }

    private static int[] mixSingleColumn(int[] a) {
        int[] b = new int[4];
        for (int i = 0; i < 4; i++) {
            b[i] = xtime(a[i]);
        }
        int col0 = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        int col1 = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        int col2 = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        int col3 = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
        return new int[]{col0, col1, col2, col3};
    }

    private static int mul(int a, int b) {
        int res = 0;
        int aa = a;
        int bb = b;
        for (int i = 0; i < 8; i++) {
            if ((bb & 1) != 0) {
                res ^= aa;
            }
            boolean hi = (aa & 0x80) != 0;
            aa = (aa << 1) & 0xFF;
            if (hi) {
                aa ^= 0x1B;
            }
            bb >>>= 1;
        }
        return res;
    }

    private static int[] invMixSingleColumn(int[] a) {
        int a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
        return new int[]{
                mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09),
                mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d),
                mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b),
                mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e)
        };
    }

    // Convert internal row-major state & round key into frontend [col][row] int matrices
    private static AESRoundStepDto makeStep(int round, String label, int[][] state, int[][] roundKey) {
        int[][] stateCM = new int[4][4];
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                stateCM[c][r] = state[r][c];
            }
        }
        return new AESRoundStepDto(round, label, stateCM, roundKey);
    }

    private static int[][] roundKeyMatrix(int[] w, int round) {
        int[][] keyCM = new int[4][4];
        byte[] keyBytes = new byte[16];
        for (int c = 0; c < 4; c++) {
            int word = w[round * 4 + c];
            keyBytes[4 * c]     = (byte) ((word >> 24) & 0xFF);
            keyBytes[4 * c + 1] = (byte) ((word >> 16) & 0xFF);
            keyBytes[4 * c + 2] = (byte) ((word >> 8) & 0xFF);
            keyBytes[4 * c + 3] = (byte) (word & 0xFF);
        }
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                keyCM[c][r] = keyBytes[c * 4 + r] & 0xFF;
            }
        }
        return keyCM;
    }
}
