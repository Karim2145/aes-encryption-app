package com.G14.aes.aes_backend.repository;

import com.G14.aes.aes_backend.entity.EncryptionRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EncryptionRepository extends JpaRepository<EncryptionRecord, Long> {

    List<EncryptionRecord> findByUserEmailOrderByCreatedAtDesc(String userEmail);
}
