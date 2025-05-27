package com.example.blockchain.controller;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.blockchain.config.XipkiSunPKCS11Config;
import com.example.blockchain.dto.KeyInfo;
import com.example.blockchain.service.XipkiEnhancedKeyService;

import lombok.extern.slf4j.Slf4j;

/**
 * Debug and monitoring controller for Xipki PKCS#11 wrapper
 */
@RestController
@RequestMapping("/api/debug/xipki")
@Slf4j
public class XipkiDebugController {

    @Autowired
    private XipkiEnhancedKeyService enhancedKeyService;

    @Autowired
    private XipkiSunPKCS11Config.ProviderInfo providerInfo;

    /**
     * Get PKCS#11 provider information
     */
    @GetMapping("/provider-info")
    public ResponseEntity<Map<String, Object>> getProviderInfo() {
        try {
            Map<String, Object> info = new HashMap<>();
            info.put("name", providerInfo.getName());
            info.put("version", providerInfo.getVersion());
            info.put("info", providerInfo.getInfo());
            info.put("status", "active");
            
            return ResponseEntity.ok(info);
        } catch (Exception e) {
            log.error("Failed to get provider info", e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            error.put("status", "error");
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Get cache statistics
     */
    @GetMapping("/cache-stats")
    public ResponseEntity<Map<String, Object>> getCacheStats() {
        try {
            Map<String, Object> stats = enhancedKeyService.getCacheStats();
            stats.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("Failed to get cache stats", e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Performance test for key retrieval and signing
     */
    @GetMapping("/performance-test/{userId}")
    public ResponseEntity<Map<String, Object>> testPerformance(@PathVariable String userId) {
        Map<String, Object> results = new HashMap<>();
        
        try {
            // Test key retrieval performance
            long startTime = System.nanoTime();
            
            for (int i = 0; i < 10; i++) {
                enhancedKeyService.getKeyPair(userId);
            }
            
            long endTime = System.nanoTime();
            long avgTimeMs = (endTime - startTime) / 10 / 1_000_000;
            
            results.put("avgKeyRetrievalMs", avgTimeMs);
            results.put("iterations", 10);
            
            // Test signing performance
            startTime = System.nanoTime();
            byte[] testData = "test data for signing performance measurement".getBytes();
            
            for (int i = 0; i < 10; i++) {
                enhancedKeyService.signData(userId, testData);
            }
            
            endTime = System.nanoTime();
            long avgSigningMs = (endTime - startTime) / 10 / 1_000_000;
            
            results.put("avgSigningMs", avgSigningMs);
            results.put("status", "success");
            results.put("timestamp", System.currentTimeMillis());
            
        } catch (Exception e) {
            log.error("Performance test failed for user: {}", userId, e);
            results.put("error", e.getMessage());
            results.put("status", "failed");
        }
        
        return ResponseEntity.ok(results);
    }

    /**
     * Generate a new key pair for testing
     */
    @PostMapping("/generate-key/{userId}")
    public ResponseEntity<Map<String, Object>> generateKey(@PathVariable String userId) {
        try {
            log.info("Generating test key for user: {}", userId);
            
            KeyPair keyPair = enhancedKeyService.generateECKeyPair(userId, userId);
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Key generated for user: " + userId);
            response.put("publicKeyAlgorithm", keyPair.getPublic().getAlgorithm());
            response.put("publicKeyFormat", keyPair.getPublic().getFormat());
            response.put("privateKeyAlgorithm", keyPair.getPrivate().getAlgorithm());
            response.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to generate key for user: {}", userId, e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Test key retrieval for a specific user
     */
    @GetMapping("/test-key/{userId}")
    public ResponseEntity<Map<String, Object>> testKey(@PathVariable String userId) {
        try {
            long startTime = System.currentTimeMillis();
            
            KeyPair keyPair = enhancedKeyService.getKeyPair(userId);
            
            long endTime = System.currentTimeMillis();
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Key found for user: " + userId);
            response.put("retrievalTimeMs", endTime - startTime);
            response.put("publicKeyAlgorithm", keyPair.getPublic().getAlgorithm());
            response.put("privateKeyAlgorithm", keyPair.getPrivate().getAlgorithm());
            response.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to retrieve key for user: {}", userId, e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Test signing operation
     */
    @PostMapping("/test-sign/{userId}")
    public ResponseEntity<Map<String, Object>> testSigning(
            @PathVariable String userId,
            @RequestBody(required = false) Map<String, String> request) {
        try {
            String testData = (request != null && request.containsKey("data")) ? 
                request.get("data") : "Default test data for signing";
            
            long startTime = System.currentTimeMillis();
            
            byte[] signature = enhancedKeyService.signData(userId, testData.getBytes());
            
            long endTime = System.currentTimeMillis();
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Data signed successfully for user: " + userId);
            response.put("signingTimeMs", endTime - startTime);
            response.put("signatureLength", signature.length);
            response.put("testDataLength", testData.length());
            response.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to sign data for user: {}", userId, e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Clear all caches (useful for testing)
     */
    @PostMapping("/clear-cache")
    public ResponseEntity<Map<String, Object>> clearCache() {
        try {
            enhancedKeyService.clearCaches();
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "All caches cleared successfully");
            response.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to clear caches", e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        
        try {
            // Test basic functionality
            Map<String, Object> cacheStats = enhancedKeyService.getCacheStats();
            
            health.put("status", "healthy");
            health.put("provider", providerInfo.getName());
            health.put("cacheEnabled", cacheStats.get("cacheEnabled"));
            health.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(health);
        } catch (Exception e) {
            log.error("Health check failed", e);
            health.put("status", "unhealthy");
            health.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(health);
        }
    }

    /**
     * Get all keys information from HSM including private-key-only entries
     */
    @GetMapping("/keys/all")
    public ResponseEntity<Map<String, Object>> getAllKeysInfo() {
        try {
            List<KeyInfo> allKeys = enhancedKeyService.getAllKeysInfo();
            
            Map<String, Object> response = new HashMap<>();
            response.put("totalKeys", allKeys.size());
            response.put("keys", allKeys);
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Retrieved {} keys from HSM", allKeys.size());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to get all keys info", e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Get private-key-only entries (keys without certificates)
     */
    @GetMapping("/keys/private-only")
    public ResponseEntity<Map<String, Object>> getPrivateOnlyKeys() {
        try {
            List<KeyInfo> privateOnlyKeys = enhancedKeyService.getPrivateOnlyKeys();
            
            Map<String, Object> response = new HashMap<>();
            response.put("privateOnlyCount", privateOnlyKeys.size());
            response.put("keys", privateOnlyKeys);
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Retrieved {} private-only keys from HSM", privateOnlyKeys.size());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to get private-only keys", e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Check if a specific key alias exists in HSM
     */
    @GetMapping("/keys/check/{alias}")
    public ResponseEntity<Map<String, Object>> checkKeyExists(@PathVariable String alias) {
        try {
            boolean exists = enhancedKeyService.hasKey(alias);
            
            Map<String, Object> response = new HashMap<>();
            response.put("alias", alias);
            response.put("exists", exists);
            response.put("timestamp", System.currentTimeMillis());
            
            if (exists) {
                // Get additional info about the key
                List<KeyInfo> allKeys = enhancedKeyService.getAllKeysInfo();
                for (KeyInfo key : allKeys) {
                    if (alias.equals(key.getAlias())) {
                        response.put("keyInfo", key);
                        break;
                    }
                }
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to check key existence for alias: {}", alias, e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            error.put("alias", alias);
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Test signing capability with a specific key alias
     */
    @PostMapping("/keys/test-signing/{alias}")
    public ResponseEntity<Map<String, Object>> testSigning(@PathVariable String alias) {
        try {
            boolean success = enhancedKeyService.testSigningWithAlias(alias);
            
            Map<String, Object> response = new HashMap<>();
            response.put("alias", alias);
            response.put("signingTest", success ? "passed" : "failed");
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Signing test for alias {} {}", alias, success ? "passed" : "failed");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to test signing with alias: {}", alias, e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            error.put("alias", alias);
            error.put("signingTest", "error");
            return ResponseEntity.internalServerError().body(error);
        }
    }
}
