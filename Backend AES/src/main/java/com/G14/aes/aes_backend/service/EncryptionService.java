package com.G14.aes.aes_backend.service;

import com.G14.aes.aes_backend.entity.EncryptionRecord;

import java.util.List;

public interface EncryptionService {

    List<EncryptionRecord> getHistoryForUser(String userEmail);

    void deleteRecord(String userEmail, Long id);

    void deleteAllForUser(String userEmail);

    EncryptionRecord saveRecord(EncryptionRecord record);
}
