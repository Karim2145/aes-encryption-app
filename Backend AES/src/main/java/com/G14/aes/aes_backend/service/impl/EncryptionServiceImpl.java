package com.G14.aes.aes_backend.service.impl;

import com.G14.aes.aes_backend.entity.EncryptionRecord;
import com.G14.aes.aes_backend.repository.EncryptionRepository;
import com.G14.aes.aes_backend.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    private final EncryptionRepository encryptionRepository;
    @Autowired
    public EncryptionServiceImpl(EncryptionRepository encryptionRepository) {
        this.encryptionRepository = encryptionRepository;
    }
    @Override
    public List<EncryptionRecord> getHistoryForUser(String userEmail) {
        return encryptionRepository.findByUserEmailOrderByCreatedAtDesc(userEmail);
    }

    @Override
    public void deleteRecord(String userEmail, Long id) {
        EncryptionRecord record = encryptionRepository.findById(id)
                .orElse(null);
        if (record != null && record.getUserEmail().equals(userEmail)) {
            encryptionRepository.delete(record);
        }
    }

    @Override
    public void deleteAllForUser(String userEmail) {
        List<EncryptionRecord> records = encryptionRepository.findByUserEmailOrderByCreatedAtDesc(userEmail);
        encryptionRepository.deleteAll(records);
    }

    @Override
    public EncryptionRecord saveRecord(EncryptionRecord record) {
        return encryptionRepository.save(record);
    }
}
