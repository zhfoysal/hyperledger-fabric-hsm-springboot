package com.example.blockchain.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import javax.annotation.PreDestroy;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import lombok.extern.slf4j.Slf4j;

/**
 * Enhanced PKCS#11 configuration using Xipki IAIK SunPKCS11 wrapper v1.4.10
 * This configuration provides better performance and more features compared to the standard SunPKCS11 provider
 */
@Configuration
@ConditionalOnProperty(name = "hsm.enhanced.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class XipkiSunPKCS11Config {

    @Value("${hsm.library:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}")
    private String hsmLibraryPath;

    @Value("${hsm.slot:1681257824}")
    private String slotId;

    @Value("${hsm.pin:98765432}")
    private String pin;

    @Value("${hsm.name:ForFabric}")
    private String tokenLabel;

    @Value("${hsm.enhanced.provider.name:XipkiPKCS11}")
    private String providerName;

    private Provider pkcs11Provider;

    /**
     * Create enhanced PKCS#11 Provider using Xipki wrapper v1.4.10
     */
    @Bean
    @Primary
    @Qualifier("pkcs11Provider")
    public Provider xipkiPkcs11Provider() throws Exception {
        log.info("Creating Xipki enhanced PKCS#11 Provider v1.4.10");
        
        try {
            // Create a temporary configuration file for Xipki
            Path tempConfigFile = Files.createTempFile("xipki-pkcs11-config", ".cfg");
            
            try {
                // Write configuration content to temporary file
                String configContent = String.format("""
                        name = %s
                        library = %s
                        slot = %s
                        """, providerName, hsmLibraryPath, slotId);
                
                Files.writeString(tempConfigFile, configContent);
                
                // Try Xipki's enhanced PKCS#11 provider first
                // For version 1.4.10, we need to use the IAIK provider class directly
                Class<?> providerClass = Class.forName("iaik.pkcs.pkcs11.provider.IAIKPkcs11");
                
                // Create provider instance with configuration file
                pkcs11Provider = (Provider) providerClass.getDeclaredConstructor(String.class)
                        .newInstance(tempConfigFile.toString());
                
                // Add to security providers with high priority
                Security.insertProviderAt(pkcs11Provider, 1);
                
                log.info("✅ Xipki PKCS#11 Provider '{}' added to Security providers", 
                        pkcs11Provider.getName());
                return pkcs11Provider;
                
            } finally {
                // Clean up temporary file
                try {
                    Files.deleteIfExists(tempConfigFile);
                } catch (Exception e) {
                    log.warn("Failed to delete temporary config file: {}", e.getMessage());
                }
            }
            
        } catch (ClassNotFoundException e) {
            log.warn("Xipki IAIK provider not found, falling back to enhanced SunPKCS11 configuration");
            return createEnhancedSunPKCS11Provider();
        } catch (Exception e) {
            log.error("Failed to create Xipki provider: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize Xipki PKCS#11 provider", e);
        }
    }

    /**
     * Create KeyStore using the enhanced provider
     */
    @Bean
    @Primary
    @Qualifier("pkcs11KeyStore")
    public KeyStore xipkiKeyStore(Provider xipkiPkcs11Provider) throws Exception {
        log.info("Creating KeyStore with Xipki provider");
        
        KeyStore keyStore = KeyStore.getInstance("PKCS11", xipkiPkcs11Provider);
        keyStore.load(null, pin.toCharArray());
        
        log.info("✅ Xipki KeyStore loaded successfully");
        return keyStore;
    }

    /**
     * Get provider information for debugging and monitoring
     */
    @Bean
    public ProviderInfo providerInfo(Provider xipkiPkcs11Provider) {
        ProviderInfo info = new ProviderInfo();
        info.setName(xipkiPkcs11Provider.getName());
        info.setVersion(xipkiPkcs11Provider.getVersionStr());
        info.setInfo(xipkiPkcs11Provider.getInfo());
        
        log.info("Provider {} version {} initialized", info.getName(), info.getVersion());
        
        return info;
    }

    /**
     * Fallback to enhanced SunPKCS11 configuration
     */
    private Provider createEnhancedSunPKCS11Provider() throws Exception {
        log.info("Creating enhanced SunPKCS11 provider as fallback");
        
        // Create a temporary configuration file
        Path tempConfigFile = Files.createTempFile("pkcs11-config", ".cfg");
        
        try {
            // Write configuration content to temporary file
            String configContent = String.format("""
                    name = %s
                    library = %s
                    slot = %s
                    attributes = compatibility
                    """, providerName, hsmLibraryPath, slotId);
            
            Files.writeString(tempConfigFile, configContent);
            
            // Create SunPKCS11 provider with configuration file
            Provider sunProvider = Security.getProvider("SunPKCS11");
            if (sunProvider == null) {
                throw new RuntimeException("SunPKCS11 provider not available");
            }

            Provider configuredProvider = sunProvider.configure(tempConfigFile.toString());
            Security.insertProviderAt(configuredProvider, 1);
            
            log.info("✅ Enhanced SunPKCS11 provider configured successfully");
            return configuredProvider;
            
        } finally {
            // Clean up temporary file
            try {
                Files.deleteIfExists(tempConfigFile);
            } catch (Exception e) {
                log.warn("Failed to delete temporary config file: {}", e.getMessage());
            }
        }
    }

    @PreDestroy
    public void cleanup() {
        try {
            if (pkcs11Provider != null) {
                Security.removeProvider(pkcs11Provider.getName());
                log.info("PKCS#11 Provider removed");
            }
        } catch (Exception e) {
            log.error("Error during cleanup", e);
        }
    }

    /**
     * Helper class for provider information
     */
    public static class ProviderInfo {
        private String name;
        private String version;
        private String info;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public String getInfo() { return info; }
        public void setInfo(String info) { this.info = info; }
    }
}
