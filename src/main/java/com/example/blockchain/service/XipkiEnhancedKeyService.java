package com.example.blockchain.service;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.blockchain.dto.KeyInfo;

import lombok.extern.slf4j.Slf4j;

/**
 * Enhanced key service using Xipki PKCS#11 wrapper v1.4.10 for improved performance
 * Provides O(1) key retrieval through intelligent caching and enhanced HSM operations
 */
@Service
@Slf4j
public class XipkiEnhancedKeyService {

    @Autowired
    @Qualifier("xipkiKeyStore")
    private KeyStore keyStore;

    @Value("${hsm.pin}")
    private String pin;

    @Value("${hsm.enhanced.cache.enabled:true}")
    private boolean cacheEnabled;

    @Value("${hsm.signature.algorithm:SHA256withECDSA}")
    private String signatureAlgorithm;

    // High-performance caches for O(1) key retrieval
    private final Map<String, KeyPair> keyPairCache = new ConcurrentHashMap<>();
    private final Map<String, String> userToKeyLabelMap = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> privateKeyCache = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeEnhancedService() {
        if (!cacheEnabled) {
            log.info("Xipki Enhanced Key Service cache disabled");
            return;
        }
        
        log.info("Initializing Xipki Enhanced Key Service v1.4.10...");
        try {
            indexExistingKeys();
            log.info("✅ Xipki Enhanced Key Service initialized with {} keys", 
                    keyPairCache.size());
        } catch (Exception e) {
            log.error("❌ Failed to initialize enhanced key service, falling back to standard mode", e);
        }
    }

    /**
     * Get key pair using enhanced caching with O(1) performance when cached
     */
    public KeyPair getKeyPair(String userId) throws Exception {
        if (cacheEnabled) {
            // Check cache first for fast retrieval
            KeyPair cachedKeyPair = keyPairCache.get(userId);
            if (cachedKeyPair != null) {
                log.debug("Retrieved key pair from cache for user: {}", userId);
                return cachedKeyPair;
            }
        }
        
        // Fallback to discovery
        return discoverAndCacheKeyPair(userId);
    }

    /**
     * Generate EC key pair using enhanced PKCS#11 operations
     */
    public KeyPair generateECKeyPair(String userId, String keyLabel) throws Exception {
        log.info("Generating EC key pair for user: {} with label: {}", userId, keyLabel);

        try {
            // Use the enhanced provider's key generation capabilities
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("EC", keyStore.getProvider());
            
            // Initialize with secp256r1 curve
            java.security.spec.ECGenParameterSpec ecSpec = new java.security.spec.ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);
            
            // Generate the key pair
            KeyPair keyPair = keyGen.generateKeyPair();
            
            // Store in HSM with the specified label
            java.security.cert.Certificate[] certChain = null; // No certificate chain for raw key generation
            KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
                    keyPair.getPrivate(), certChain
            );

            keyStore.setEntry(
                    keyLabel,
                    privateKeyEntry,
                    new KeyStore.PasswordProtection(pin.toCharArray())
            );
            
            // Cache the key pair
            if (cacheEnabled) {
                keyPairCache.put(userId, keyPair);
                userToKeyLabelMap.put(userId, keyLabel);
                privateKeyCache.put(userId, keyPair.getPrivate());
            }
            
            log.info("✅ Generated EC key pair for user: {}", userId);
            return keyPair;
            
        } catch (Exception e) {
            log.error("Failed to generate key pair using enhanced API: {}", e.getMessage(), e);
            throw new RuntimeException("Enhanced key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Sign data using enhanced signing with the configured provider
     */
    public byte[] signData(String userId, byte[] data) throws Exception {
        try {
            // Get private key (cached or from HSM)
            PrivateKey privateKey = getPrivateKey(userId);
            
            // Create signature instance with the enhanced provider
            Signature signature = Signature.getInstance(signatureAlgorithm, keyStore.getProvider());
            signature.initSign(privateKey);
            signature.update(data);
            
            long startTime = System.currentTimeMillis();
            byte[] result = signature.sign();
            long endTime = System.currentTimeMillis();
            
            log.debug("Enhanced signing took {} ms for user: {}", (endTime - startTime), userId);
            return result;
            
        } catch (Exception e) {
            log.warn("Enhanced signing failed, falling back to standard method: {}", e.getMessage());
            return signDataStandard(userId, data);
        }
    }

    /**
     * Enhanced key discovery with better performance
     */
    private KeyPair discoverAndCacheKeyPair(String userId) throws Exception {
        log.info("Discovering key pair for user: {}", userId);

        // Try common key label patterns first
        String[] labelPatterns = {
            userId,
            userId.toLowerCase(),
            userId.toUpperCase(),
            "user_" + userId,
            userId + "_key",
            userId.replace("-", "")
        };

        for (String pattern : labelPatterns) {
            try {
                KeyPair keyPair = getKeyPairByLabel(pattern);
                if (keyPair != null) {
                    // Cache the mapping and key pair
                    if (cacheEnabled) {
                        userToKeyLabelMap.put(userId, pattern);
                        keyPairCache.put(userId, keyPair);
                        privateKeyCache.put(userId, keyPair.getPrivate());
                    }
                    
                    log.info("✅ Discovered key pair for user: {} with label: {}", userId, pattern);
                    return keyPair;
                }
            } catch (Exception e) {
                log.debug("Pattern {} failed for user {}: {}", pattern, userId, e.getMessage());
            }
        }

        // Enhanced discovery using HSM enumeration
        return discoverUsingHSMEnumeration(userId);
    }

    /**
     * Get key pair by label using KeyStore
     */
    private KeyPair getKeyPairByLabel(String label) throws Exception {
        try {
            if (keyStore.containsAlias(label) && keyStore.isKeyEntry(label)) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(label, pin.toCharArray());
                if (privateKey != null) {
                    // Try to get certificate for public key
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(label);
                    if (cert != null) {
                        return new KeyPair(cert.getPublicKey(), privateKey);
                    }
                    
                    // If no certificate, try to derive public key from private key
                    PublicKey publicKey = derivePublicKeyFromPrivate(privateKey);
                    if (publicKey != null) {
                        return new KeyPair(publicKey, privateKey);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Failed to get key pair by label: {}", label, e);
        }
        return null;
    }

    /**
     * Enhanced discovery using HSM key enumeration
     */
    private KeyPair discoverUsingHSMEnumeration(String userId) throws Exception {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                if (couldBelongToUser(alias, userId)) {
                    try {
                        KeyPair keyPair = getKeyPairByLabel(alias);
                        if (keyPair != null) {
                            // Cache the key pair
                            if (cacheEnabled) {
                                userToKeyLabelMap.put(userId, alias);
                                keyPairCache.put(userId, keyPair);
                                privateKeyCache.put(userId, keyPair.getPrivate());
                            }
                            
                            log.info("🔍 Discovered key pair for user: {} with alias: {}", userId, alias);
                            return keyPair;
                        }
                    } catch (Exception e) {
                        log.debug("Failed to get key pair for alias: {}", alias, e);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Enhanced HSM enumeration failed: {}", e.getMessage());
        }
        
        throw new RuntimeException("No key pair found for user: " + userId);
    }

    /**
     * Index existing keys for fast access
     */
    private void indexExistingKeys() throws Exception {
        log.info("Indexing existing keys...");

        try {
            Enumeration<String> aliases = keyStore.aliases();
            int indexedCount = 0;
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                try {
                    if (keyStore.isKeyEntry(alias)) {
                        // Extract potential user ID from alias
                        String userId = extractUserIdFromLabel(alias);
                        if (userId != null) {
                            KeyPair keyPair = getKeyPairByLabel(alias);
                            if (keyPair != null) {
                                keyPairCache.put(userId, keyPair);
                                userToKeyLabelMap.put(userId, alias);
                                privateKeyCache.put(userId, keyPair.getPrivate());
                                indexedCount++;
                                log.debug("Indexed key: {} -> {}", userId, alias);
                            }
                        }
                    }
                } catch (Exception e) {
                    log.debug("Failed to index alias: {}", alias, e);
                }
            }
            
            log.info("Indexed {} keys", indexedCount);
        } catch (Exception e) {
            log.warn("Failed to index keys: {}", e.getMessage(), e);
        }
    }

    /**
     * Get private key for user (cached or from HSM)
     */
    private PrivateKey getPrivateKey(String userId) throws Exception {
        if (cacheEnabled) {
            PrivateKey cachedKey = privateKeyCache.get(userId);
            if (cachedKey != null) {
                return cachedKey;
            }
        }
        
        // Get key pair and extract private key
        KeyPair keyPair = getKeyPair(userId);
        return keyPair.getPrivate();
    }

    /**
     * Standard signing fallback method
     */
    private byte[] signDataStandard(String userId, byte[] data) throws Exception {
        KeyPair keyPair = getKeyPair(userId);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    /**
     * Derive public key from private key (simplified implementation)
     */
    private PublicKey derivePublicKeyFromPrivate(PrivateKey privateKey) {
        // This is a simplified implementation
        // In practice, you might need more sophisticated key derivation
        try {
            if (privateKey.getAlgorithm().equals("EC")) {
                // For EC keys, we would need to derive the public key from the private key
                // This is complex and provider-specific
                log.debug("EC public key derivation not implemented in simplified version");
            }
        } catch (Exception e) {
            log.debug("Failed to derive public key: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extract user ID from HSM label
     */
    private String extractUserIdFromLabel(String label) {
        if (label == null || label.trim().isEmpty()) {
            return null;
        }
        
        // Remove common prefixes/suffixes
        String cleaned = label.trim();
        if (cleaned.startsWith("user_")) {
            cleaned = cleaned.substring(5);
        }
        if (cleaned.endsWith("_key")) {
            cleaned = cleaned.substring(0, cleaned.length() - 4);
        }
        
        // Validate as potential user ID (UUID format, etc.)
        if (isValidUserId(cleaned)) {
            return cleaned;
        }
        
        return label; // Return original if no pattern matches
    }

    /**
     * Check if label could belong to user
     */
    private boolean couldBelongToUser(String label, String userId) {
        if (label == null || userId == null) {
            return false;
        }
        
        String lowerLabel = label.toLowerCase();
        String lowerUserId = userId.toLowerCase();
        
        return lowerLabel.contains(lowerUserId) || lowerUserId.contains(lowerLabel);
    }

    /**
     * Validate user ID format
     */
    private boolean isValidUserId(String candidate) {
        if (candidate == null || candidate.trim().isEmpty()) {
            return false;
        }
        
        // Check for UUID pattern
        if (candidate.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            return true;
        }
        
        // Add other validation logic as needed
        return candidate.length() > 2; // Basic length check
    }

    /**
     * Get cache statistics for monitoring
     */
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        stats.put("keyPairs", keyPairCache.size());
        stats.put("labelMappings", userToKeyLabelMap.size());
        stats.put("privateKeys", privateKeyCache.size());
        stats.put("cacheEnabled", cacheEnabled);
        stats.put("providerName", keyStore.getProvider().getName());
        stats.put("providerVersion", keyStore.getProvider().getVersionStr());
        return stats;
    }

    /**
     * Clear all caches - useful for testing or troubleshooting
     */
    public void clearCaches() {
        keyPairCache.clear();
        userToKeyLabelMap.clear();
        privateKeyCache.clear();
        log.info("All caches cleared");
    }

    /**
     * Get all keys information from HSM including private-key-only entries
     */
    public List<KeyInfo> getAllKeysInfo() {
        List<KeyInfo> keyInfoList = new ArrayList<>();
        
        try {
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                try {
                    KeyInfo keyInfo = createKeyInfo(alias);
                    if (keyInfo != null) {
                        keyInfoList.add(keyInfo);
                    }
                } catch (Exception e) {
                    log.debug("Could not process alias {}: {}", alias, e.getMessage());
                }
            }
            
            log.info("Found {} total keys in HSM", keyInfoList.size());
        } catch (Exception e) {
            log.error("Failed to enumerate all keys", e);
        }
        
        return keyInfoList;
    }

    /**
     * Get private-key-only entries (keys without certificates)
     */
    public List<KeyInfo> getPrivateOnlyKeys() {
        return getAllKeysInfo().stream()
                .filter(keyInfo -> keyInfo.isHasPrivateKey() && !keyInfo.isHasCertificate())
                .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Check if a specific key alias exists in HSM
     */
    public boolean hasKey(String alias) {
        try {
            return keyStore.containsAlias(alias);
        } catch (Exception e) {
            log.error("Failed to check if alias {} exists", alias, e);
            return false;
        }
    }

    /**
     * Get private key by alias
     */
    public PrivateKey getPrivateKeyByAlias(String alias) {
        try {
            if (!keyStore.isKeyEntry(alias)) {
                return null;
            }
            
            Key key = keyStore.getKey(alias, null);
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
        } catch (Exception e) {
            log.error("Failed to retrieve private key for alias: {}", alias, e);
        }
        return null;
    }

    /**
     * Test signing capability with a specific key alias
     */
    public boolean testSigningWithAlias(String alias) {
        try {
            PrivateKey privateKey = getPrivateKeyByAlias(alias);
            if (privateKey == null) {
                log.warn("No private key found for alias: {}", alias);
                return false;
            }
            
            // Determine signature algorithm based on key type
            String algorithm;
            if (privateKey.getAlgorithm().equals("EC")) {
                algorithm = "SHA256withECDSA";
            } else if (privateKey.getAlgorithm().equals("RSA")) {
                algorithm = "SHA256withRSA";
            } else {
                log.warn("Unsupported key algorithm for signing test: {}", privateKey.getAlgorithm());
                return false;
            }
            
            // Test signing
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            
            byte[] testData = "test data for signing verification".getBytes();
            signature.update(testData);
            byte[] signatureBytes = signature.sign();
            
            log.debug("Successfully signed test data with alias {} - signature length: {}", 
                    alias, signatureBytes.length);
            return true;
            
        } catch (Exception e) {
            log.error("Failed to test signing with alias: {}", alias, e);
            return false;
        }
    }

    /**
     * Helper method to create KeyInfo from alias
     */
    private KeyInfo createKeyInfo(String alias) {
        try {
            boolean hasPrivateKey = keyStore.isKeyEntry(alias);
            boolean hasCertificate = keyStore.isCertificateEntry(alias) || 
                                   (hasPrivateKey && keyStore.getCertificate(alias) != null);
            
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.setAlias(alias);
            keyInfo.setHasPrivateKey(hasPrivateKey);
            keyInfo.setHasCertificate(hasCertificate);
            
            // Determine source and key type
            if (hasPrivateKey && !hasCertificate) {
                keyInfo.setSource("CLI_GENERATED");
                keyInfo.setKeyType("PRIVATE_ONLY");
            } else if (hasPrivateKey && hasCertificate) {
                keyInfo.setSource("APPLICATION_GENERATED");
                keyInfo.setKeyType("KEYPAIR_WITH_CERT");
            } else if (hasCertificate) {
                keyInfo.setSource("IMPORTED");
                keyInfo.setKeyType("CERTIFICATE_ONLY");
            }
            
            // Get key algorithm and size if it's a private key
            if (hasPrivateKey) {
                try {
                    Key key = keyStore.getKey(alias, null);
                    if (key instanceof PrivateKey) {
                        PrivateKey privateKey = (PrivateKey) key;
                        keyInfo.setAlgorithm(privateKey.getAlgorithm());
                        
                        Integer keySize = null;
                        if ("EC".equals(privateKey.getAlgorithm())) {
                            keySize = getECKeySize(privateKey);
                        } else if ("RSA".equals(privateKey.getAlgorithm())) {
                            keySize = getRSAKeySize(privateKey);
                        }
                        keyInfo.setKeySize(keySize);
                    }
                } catch (Exception e) {
                    log.debug("Could not determine key details for alias {}: {}", alias, e.getMessage());
                }
            }
            
            return keyInfo;
        } catch (Exception e) {
            log.error("Failed to create KeyInfo for alias: {}", alias, e);
            return null;
        }
    }

    /**
     * Helper method to get EC key size
     */
    private Integer getECKeySize(PrivateKey privateKey) {
        try {
            if (privateKey instanceof java.security.interfaces.ECKey) {
                java.security.interfaces.ECKey ecKey = (java.security.interfaces.ECKey) privateKey;
                return ecKey.getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception e) {
            log.debug("Could not determine EC key size", e);
        }
        return null;
    }

    /**
     * Helper method to get RSA key size
     */
    private Integer getRSAKeySize(PrivateKey privateKey) {
        try {
            if (privateKey instanceof java.security.interfaces.RSAKey) {
                java.security.interfaces.RSAKey rsaKey = (java.security.interfaces.RSAKey) privateKey;
                return rsaKey.getModulus().bitLength();
            }
        } catch (Exception e) {
            log.debug("Could not determine RSA key size", e);
        }
        return null;
    }
}
