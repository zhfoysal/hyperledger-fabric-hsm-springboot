package com.example.blockchain.dto;

import lombok.Data;

/**
 * Information about a key stored in HSM
 */
@Data
public class KeyInfo {
    private String alias;
    private boolean hasPrivateKey;
    private boolean hasCertificate;
    private String keyType;
    private String source; // "KEYSTORE_WITH_CERT", "PRIVATE_KEY_ONLY", etc.
    private String algorithm;
    private Integer keySize;
}
