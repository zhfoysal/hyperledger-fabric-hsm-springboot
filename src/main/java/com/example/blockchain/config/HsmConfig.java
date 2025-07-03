package com.example.blockchain.config;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.extern.slf4j.Slf4j;

/**
 * Configuration for Hardware Security Module (HSM) integration
 */
@Slf4j
@Configuration
public class HsmConfig {

    @Value("${hsm.name}")
    private String hsmName;

    @Value("${hsm.library}")
    private String hsmLibrary;

    @Value("${hsm.slot}")
    private String hsmSlot;

    @Value("${hsm.pin}")
    private String hsmPin;

    /**
     * Configures and provides the PKCS11 provider for HSM integration
     */
    @Bean
    @Qualifier("pkcs11Provider")
    public Provider pkcs11Provider() {
        try {
            String config = String.format("""
                    --name = %s
                    library = %s
                    slot = %s
                    """, hsmName, hsmLibrary, hsmSlot);

            Provider pkcs11Provider = Security.getProvider("SunPKCS11");
            pkcs11Provider = pkcs11Provider.configure(config);
            Security.addProvider(pkcs11Provider);

            log.info("Successfully configured PKCS11 provider for HSM: {}", hsmName);
            return pkcs11Provider;
        } catch (Exception e) {
            log.error("Failed to configure PKCS11 provider: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize HSM configuration", e);
        }
    }

    /**
     * Creates a KeyStore that uses the configured PKCS11 provider
     */
    @Bean
    @Qualifier("pkcs11KeyStore")
    public KeyStore pkcs11KeyStore(@Qualifier("pkcs11Provider") Provider pkcs11Provider) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            keyStore.load(null, hsmPin.toCharArray());
            log.info("Successfully loaded PKCS11 KeyStore");
            
            // Print all keys found in the keystore
            printKeyStoreContents(keyStore);
            
            return keyStore;
        } catch (Exception e) {
            log.error("Failed to load PKCS11 KeyStore: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize HSM KeyStore", e);
        }
    }

    /**
     * Prints all keys and certificates found in the keystore
     */
    private void printKeyStoreContents(KeyStore keyStore) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            int keyCount = 0;
            int certCount = 0;
            StringBuilder result = new StringBuilder();
            result.append("=== KeyStore Contents ===\n");
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                if (keyStore.isKeyEntry(alias)) {
                    result.append("Private Key found - Alias: ").append(alias).append("\n");
                    keyCount++;
                } else if (keyStore.isCertificateEntry(alias)) {
                    result.append("Certificate found - Alias: ").append(alias).append("\n");
                    certCount++;
                }
            }
            
            result.append("Total keys found: ").append(keyCount).append(" private keys, ").append(certCount).append(" certificates\n");
            result.append("=== End KeyStore Contents ===");
            
            log.info(result.toString());
            
        } catch (Exception e) {
            log.warn("Failed to enumerate keystore contents: {}", e.getMessage());
        }
    }
}
