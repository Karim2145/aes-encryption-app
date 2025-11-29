package com.G14.aes.aes_backend.aes;

import com.G14.aes.aes_backend.dto.*;
import com.G14.aes.aes_backend.entity.EncryptionRecord;
import com.G14.aes.aes_backend.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AESService {

    private final EncryptionService encryptionService;

    // ========= PUBLIC METHODS =========

    public MultiBlockEncryptionResultDto encryptFullText(
            EncryptFullTextRequest request,
            String userEmail
    ) {
        byte[] key = hexToBytes(request.getKeyHex());
        int keySize = request.getKeySize();
        validateKeyLength(key, keySize);

        String mode = request.getMode().toUpperCase();

        // Plaintext is HEX (message in hex)
        byte[] plaintext = hexToBytes(request.getPlaintext());

        boolean isStreamMode =
                mode.equals("CFB") || mode.equals("OFB") || mode.equals("CTR");
        boolean isBlockMode =
                mode.equals("ECB") || mode.equals("CBC");

        // --- padding logic ---
        byte[] workingPlain;
        int padLen;
        if (isStreamMode) {
            // No padding for CFB / OFB / CTR
            workingPlain = plaintext;
            padLen = 0;
        } else if (isBlockMode) {
            workingPlain = pkcs7Pad(plaintext, 16);
            padLen = workingPlain.length - plaintext.length;
        } else {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        }

        int blockCount = (workingPlain.length + 15) / 16;

        // separate IV (for CBC/CFB/OFB) and counter (for CTR)
        byte[] iv = deriveIvOrCounter(request.getIvHex());
        byte[] ctrCounter = deriveIvOrCounter(request.getCtrCounterHex());

        // For stream modes, ciphertext length = plaintext length
        byte[] fullCipher = isStreamMode
                ? new byte[plaintext.length]
                : new byte[workingPlain.length];

        List<MultiBlockEncryptionBlockResultDto> blockResults = new ArrayList<>();
        StringBuilder ciphertextHexBuilder = new StringBuilder();

        // CBC/CFB use prevCipher; OFB uses prevOfb
        byte[] prevCipher = Arrays.copyOf(iv, 16);
        byte[] prevOfb = Arrays.copyOf(iv, 16);

        for (int i = 0; i < blockCount; i++) {
            int start = i * 16;
            int blockSize = Math.min(16, workingPlain.length - start);

            // always build a 16-byte block for AES core
            byte[] ptBlock16 = new byte[16];
            System.arraycopy(workingPlain, start, ptBlock16, 0, blockSize);

            byte[] aesInput;
            byte[] aesOutput;
            byte[] ctBlock16;

            AesCore.AesBlockTrace trace;

            switch (mode) {
                case "ECB" -> {
                    aesInput = ptBlock16;
                    trace = AesCore.encryptBlockWithTrace(aesInput, key);
                    aesOutput = trace.getOutput();
                    ctBlock16 = aesOutput;
                }
                case "CBC" -> {
                    aesInput = xorBlocks(ptBlock16, prevCipher);
                    trace = AesCore.encryptBlockWithTrace(aesInput, key);
                    aesOutput = trace.getOutput();
                    ctBlock16 = aesOutput;
                    prevCipher = ctBlock16;
                }
                case "CFB" -> {
                    aesInput = prevCipher;
                    trace = AesCore.encryptBlockWithTrace(aesInput, key);
                    aesOutput = trace.getOutput(); // keystream
                    ctBlock16 = xorBlocks(ptBlock16, aesOutput);
                    prevCipher = ctBlock16;
                }
                case "OFB" -> {
                    aesInput = prevOfb;
                    trace = AesCore.encryptBlockWithTrace(aesInput, key);
                    aesOutput = trace.getOutput(); // keystream
                    ctBlock16 = xorBlocks(ptBlock16, aesOutput);
                    prevOfb = aesOutput;
                }
                case "CTR" -> {
                    aesInput = ctrCounter;
                    trace = AesCore.encryptBlockWithTrace(aesInput, key);
                    aesOutput = trace.getOutput(); // keystream
                    ctBlock16 = xorBlocks(ptBlock16, aesOutput);
                    incrementCounter(ctrCounter);
                }
                default -> throw new IllegalArgumentException("Unsupported mode: " + mode);
            }

            // For logging / UI, we only use the *real* bytes of this block
            byte[] ptBlockUsed = Arrays.copyOf(ptBlock16, blockSize);
            byte[] ctBlockUsed = Arrays.copyOf(ctBlock16, blockSize);

            // Copy into fullCipher
            if (isStreamMode) {
                // stream modes: ciphertext exactly same length as plaintext
                System.arraycopy(ctBlockUsed, 0, fullCipher, start, blockSize);
            } else {
                // block modes: always full 16-byte blocks (with padding)
                System.arraycopy(ctBlock16, 0, fullCipher, start, 16);
            }

            String ptHex = bytesToHex(ptBlockUsed);

            // What we actually want to *show* as "ciphertext" in the UI:
            byte[] visCipher = isStreamMode ? ctBlockUsed : ctBlock16;
            String ctHex = bytesToHex(visCipher);
            ciphertextHexBuilder.append(ctHex);

            MultiBlockEncryptionBlockResultDto blockDto = new MultiBlockEncryptionBlockResultDto();
            blockDto.setBlockIndex(i);
            blockDto.setPlaintextBlockHex(ptHex);
            blockDto.setCiphertextBlockHex(ctHex);

            // give the visualization the real ciphertext bytes
            blockDto.setAesResult(toAesResultDto(visCipher, trace.getSteps()));
            blockResults.add(blockDto);
        }

        MultiBlockEncryptionResultDto result = new MultiBlockEncryptionResultDto();
        result.setMode(mode);
        result.setBlockResults(blockResults);
        result.setCiphertextHex(ciphertextHexBuilder.toString());

        if (isStreamMode) {
            result.setPaddingDescription(
                    "No padding used in " + mode + " mode (stream-like)."
            );
        } else {
            result.setPaddingDescription(
                    "PKCS#7 padding with " + padLen + " byte(s) on the last block."
            );
        }

        // Log history (plaintext here is hex string)
        EncryptionRecord record = EncryptionRecord.builder()
                .algorithm("AES-" + keySize)
                .mode(mode)
                .operation("ENCRYPT")
                .plaintext(request.getPlaintext())
                .ciphertext(result.getCiphertextHex())
                .keyUsed(request.getKeyHex())
                .userEmail(userEmail)
                .blockCount(blockCount)
                .ivUsed(request.getIvHex())              // NULL is allowed
                .ctrUsed(request.getCtrCounterHex())     // NULL is allowed
                .build();

        encryptionService.saveRecord(record);

        return result;
    }


    public MultiBlockDecryptionResultDto decryptFullText(
            DecryptFullTextRequest request,
            String userEmail
    ) {
        byte[] key = hexToBytes(request.getKeyHex());
        int keySize = request.getKeySize();
        validateKeyLength(key, keySize);

        String mode = request.getMode().toUpperCase();
        byte[] ciphertext = hexToBytes(request.getCiphertextHex());

        boolean isStreamMode =
                mode.equals("CFB") || mode.equals("OFB") || mode.equals("CTR");
        boolean isBlockMode =
                mode.equals("ECB") || mode.equals("CBC");

        if (isBlockMode && (ciphertext.length % 16 != 0)) {
            throw new IllegalArgumentException(
                    "Ciphertext length must be multiple of 16 bytes for " + mode + "."
            );
        }

        int blockCount = (ciphertext.length + 15) / 16;

        // separate IV and counter, mirroring encryption
        byte[] iv = deriveIvOrCounter(request.getIvHex());
        byte[] ctrCounter = deriveIvOrCounter(request.getCtrCounterHex());

        byte[] fullPlain = new byte[ciphertext.length];

        List<MultiBlockDecryptionBlockResultDto> blockResults = new ArrayList<>();

        byte[] prevCipher = Arrays.copyOf(iv, 16);
        byte[] prevOfb = Arrays.copyOf(iv, 16);

        for (int i = 0; i < blockCount; i++) {
            int start = i * 16;
            int blockSize = Math.min(16, ciphertext.length - start);

            byte[] ctBlock16 = new byte[16];
            System.arraycopy(ciphertext, start, ctBlock16, 0, blockSize);

            byte[] ptBlock16;
            AesCore.AesBlockTrace trace;

            switch (mode) {
                case "ECB" -> {
                    trace = AesCore.decryptBlockWithTrace(ctBlock16, key);
                    ptBlock16 = trace.getOutput();
                }
                case "CBC" -> {
                    trace = AesCore.decryptBlockWithTrace(ctBlock16, key);
                    byte[] decrypted = trace.getOutput();
                    ptBlock16 = xorBlocks(decrypted, prevCipher);
                    prevCipher = ctBlock16;
                }
                case "CFB" -> {
                    // CFB decryption uses AES encryption of prevCipher to get keystream
                    trace = AesCore.encryptBlockWithTrace(prevCipher, key);
                    byte[] keystream = trace.getOutput();
                    ptBlock16 = xorBlocks(ctBlock16, keystream);
                    prevCipher = ctBlock16;
                }
                case "OFB" -> {
                    // OFB decryption uses same keystream as encryption
                    trace = AesCore.encryptBlockWithTrace(prevOfb, key);
                    byte[] keystream = trace.getOutput();
                    ptBlock16 = xorBlocks(ctBlock16, keystream);
                    prevOfb = keystream;
                }
                case "CTR" -> {
                    trace = AesCore.encryptBlockWithTrace(ctrCounter, key);
                    byte[] keystream = trace.getOutput();
                    ptBlock16 = xorBlocks(ctBlock16, keystream);
                    incrementCounter(ctrCounter);
                }
                default -> throw new IllegalArgumentException("Unsupported mode: " + mode);
            }

            byte[] ctBlockUsed = Arrays.copyOf(ctBlock16, blockSize);
            byte[] ptBlockUsed = Arrays.copyOf(ptBlock16, blockSize);

            System.arraycopy(ptBlockUsed, 0, fullPlain, start, blockSize);

            String ctHex = bytesToHex(ctBlockUsed);
            String ptHex = bytesToHex(ptBlockUsed);

            MultiBlockDecryptionBlockResultDto blockDto =
                    new MultiBlockDecryptionBlockResultDto();
            blockDto.setBlockIndex(i);
            blockDto.setCiphertextBlockHex(ctHex);
            blockDto.setPlaintextBlockHex(ptHex);

            // For decryption view, visualize the plaintext bytes:
            blockDto.setAesResult(toAesResultDto(ptBlockUsed, trace.getSteps()));
            blockResults.add(blockDto);
        }

        byte[] finalPlain;
        String paddingDescription;

        if (isBlockMode) {
            byte[] unpadded = pkcs7Unpad(fullPlain, 16);
            finalPlain = unpadded;
            paddingDescription = "PKCS#7 padding removed on the last block.";
        } else {
            finalPlain = fullPlain;
            paddingDescription = "No padding used in " + mode + " mode (stream-like).";
        }

        // For logging / download; UI mainly uses plaintextHex
        String plaintext = new String(finalPlain, StandardCharsets.UTF_8);
        String plaintextHex = bytesToHex(finalPlain);

        MultiBlockDecryptionResultDto result = new MultiBlockDecryptionResultDto();
        result.setMode(mode);
        result.setBlockResults(blockResults);
        result.setPlaintextHex(plaintextHex);
        result.setPaddingDescription(paddingDescription);

        EncryptionRecord record = EncryptionRecord.builder()
                .algorithm("AES-" + keySize)
                .mode(mode)
                .operation("DECRYPT")
                .plaintext(plaintext)
                .ciphertext(request.getCiphertextHex())
                .keyUsed(request.getKeyHex())
                .userEmail(userEmail)
                .blockCount(blockCount)
                .ivUsed(request.getIvHex())              // NULL allowed
                .ctrUsed(request.getCtrCounterHex())     // NULL allowed
                .build();

        encryptionService.saveRecord(record);

        return result;
    }


    // ========= INTERNAL HELPERS =========

    private void validateKeyLength(byte[] key, int keySize) {
        int expected = keySize / 8;
        if (key.length != expected) {
            throw new IllegalArgumentException(
                    "Key must be " + expected + " bytes for AES-" + keySize
            );
        }
    }

    private byte[] pkcs7Pad(byte[] data, int blockSize) {
        int padLen = blockSize - (data.length % blockSize);
        if (padLen == 0) padLen = blockSize;
        byte[] out = Arrays.copyOf(data, data.length + padLen);
        Arrays.fill(out, data.length, out.length, (byte) padLen);
        return out;
    }

    private byte[] pkcs7Unpad(byte[] data, int blockSize) {
        if (data.length == 0 || data.length % blockSize != 0) {
            throw new IllegalArgumentException("Invalid padded data length.");
        }
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen < 1 || padLen > blockSize) {
            throw new IllegalArgumentException("Invalid PKCS#7 padding length.");
        }
        for (int i = data.length - padLen; i < data.length; i++) {
            if ((data[i] & 0xFF) != padLen) {
                throw new IllegalArgumentException("Invalid PKCS#7 padding bytes.");
            }
        }
        return Arrays.copyOf(data, data.length - padLen);
    }

    private byte[] xorBlocks(byte[] a, byte[] b) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if ((counter[i] & 0xFF) != 0) break;
        }
    }

    // derive IV / counter from hex (right-aligned, zero-padded)
    private byte[] deriveIvOrCounter(String hex) {
        byte[] iv = new byte[16]; // all zeros by default
        if (hex == null || hex.isBlank()) {
            return iv;
        }
        byte[] raw = hexToBytes(hex);
        if (raw.length >= 16) {
            System.arraycopy(raw, raw.length - 16, iv, 0, 16);
        } else {
            System.arraycopy(raw, 0, iv, 16 - raw.length, raw.length);
        }
        return iv;
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null) return new byte[0];
        String clean = hex.replaceAll("\\s+", "");
        if (clean.isEmpty()) return new byte[0];

        // safety: if odd length, pad with a leading 0
        if ((clean.length() & 1) == 1) {
            clean = "0" + clean;
        }

        int len = clean.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int b = Integer.parseInt(clean.substring(i, i + 2), 16);
            out[i / 2] = (byte) b;
        }
        return out;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private AESEncryptionResultDto toAesResultDto(byte[] aesOutput, List<AESRoundStepDto> steps) {
        AESEncryptionResultDto dto = new AESEncryptionResultDto();
        List<Integer> bytesList = new ArrayList<>(aesOutput.length);
        for (byte b : aesOutput) {
            bytesList.add(b & 0xFF);
        }
        dto.setCiphertext(bytesList);
        dto.setSteps(steps);
        return dto;
    }
}
