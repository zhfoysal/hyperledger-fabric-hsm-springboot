package com.example.blockchain.service;

import com.example.blockchain.api.dto.response.EnrollmentResponse;
import com.example.blockchain.exception.BlockchainException;
import com.example.blockchain.util.CertificateUtil;
import com.example.blockchain.util.CryptoUtil;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class AdminServiceImpl implements AdminService {

    private final HFCAClient caClient;
    private final Provider pkcs11Provider;
    private final KeyStore pkcs11KeyStore;
    private volatile User caAdmin;

    @Value("${ca-admin.name}")
    private String caAdminName;

    @Value("${ca-admin.password}")
    private String caAdminPassword;

    @Value("${ca-admin.org-name}")
    private String caAdminOrgName;

    @Value("${fabric.msp-id}")
    private String mspId;

    @Value("${hsm.pin}")
    private String hsmPin;

    @Value("${file.certs.dir}")
    private String certsDir;

    @Value("${file.keys.dir}")
    private String keysDir;

    @Value("${file.cert-suffix}")
    private String certSuffix;

    @Value("${file.priv-key-suffix}")
    private String privKeySuffix;

    public AdminServiceImpl(
            HFCAClient caClient,
            @Qualifier("pkcs11Provider") Provider pkcs11Provider,
            @Qualifier("pkcs11KeyStore") KeyStore pkcs11KeyStore) {
        this.caClient = caClient;
        this.pkcs11Provider = pkcs11Provider;
        this.pkcs11KeyStore = pkcs11KeyStore;
    }

    @Override
    public EnrollmentResponse registerAdmin(UUID adminId) {
        try {
            String adminIdStr = adminId.toString();
            log.info("Registering new admin user with ID: {}", adminIdStr);

            // Generate key pair in HSM
            KeyPair keyPair = generateHsmKeyPair();
            String csr = CryptoUtil.generateCsr(keyPair, adminIdStr);

            // Register the admin with the CA
            String enrollmentSecret = registerAdminWithCA(adminIdStr);

            // Enroll the admin with the CSR
            Enrollment enrollment = enrollAdmin(adminIdStr, enrollmentSecret, csr, keyPair);

            // Store the key pair and certificate in HSM
            storeAdminKeyPair(adminIdStr, keyPair, enrollment.getCert());

            // Calculate blockchain address
            String bcAddress = CryptoUtil.sha256Hash(
                    CertificateUtil.getUserID(enrollment.getCert().getBytes()));

            return EnrollmentResponse.builder()
                    .userId(adminId)
                    .blockchainAddress(bcAddress)
                    .certificate(enrollment.getCert())
                    .certificateSecret(enrollmentSecret)
                    .build();
        } catch (Exception e) {
            log.error("Failed to register admin: {}", e.getMessage(), e);
            throw new BlockchainException("Failed to register admin: " + e.getMessage());
        }
    }

    /**
     * Register an admin with the Fabric CA
     */
    private String registerAdminWithCA(String adminId) throws Exception {
        User caAdmin = getCaAdmin();
        org.hyperledger.fabric_ca.sdk.RegistrationRequest registrationRequest =
            new org.hyperledger.fabric_ca.sdk.RegistrationRequest(adminId, "org1.department1");
        registrationRequest.setMaxEnrollments(-1);
        registrationRequest.addAttribute(new org.hyperledger.fabric_ca.sdk.Attribute("admin", "true"));
        return caClient.register(registrationRequest, caAdmin);
    }

    /**
     * Enroll an admin with the Fabric CA using a CSR
     */
    private Enrollment enrollAdmin(String adminId, String secret, String csr, KeyPair keyPair) throws Exception {
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setCsr(csr);
        enrollmentRequest.setKeyPair(keyPair);
        return caClient.enroll(adminId, secret, enrollmentRequest);
    }

    @Override
    public User getCaAdmin() {
        if (caAdmin == null) {
            synchronized (this) {
                if (caAdmin == null) {
                    try {
                        caAdmin = loadCaAdmin();
                    } catch (Exception e) {
                        log.error("Failed to load CA admin: {}", e.getMessage(), e);
                        throw new BlockchainException("Failed to load CA admin: " + e.getMessage());
                    }
                }
            }
        }
        return caAdmin;
    }

    /**
     * Generate a key pair in the HSM
     */
    private KeyPair generateHsmKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", pkcs11Provider);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256 curve
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Store the admin key pair and certificate - private key in HSM, certificate in filesystem
     */
    private void storeAdminKeyPair(String adminId, KeyPair keyPair, String certificate) throws Exception {
        // Store certificate to file system for reference only
        Path certPath = Paths.get(certsDir, adminId + certSuffix);
        Files.createDirectories(certPath.getParent());
        Files.writeString(certPath, certificate);

        // Store private key exclusively in HSM
        java.security.cert.Certificate[] certChain = {
                CryptoUtil.convertPemToCertificate(certificate)
        };

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
                keyPair.getPrivate(), certChain
        );

        pkcs11KeyStore.setEntry(
                adminId,
                privateKeyEntry,
                new KeyStore.PasswordProtection(hsmPin.toCharArray())
        );

        log.info("Admin private key stored in HSM and certificate in filesystem for admin ID: {}", adminId);
    }

    /**
     * Load the CA admin from filesystem or HSM
     */
    private User loadCaAdmin() throws Exception {
        // Check if we have existing CA admin credentials on disk
        Path certPath = Paths.get(certsDir, caAdminOrgName + certSuffix);
        Path keyPath = Paths.get(keysDir, caAdminOrgName + privKeySuffix);

        if (Files.exists(certPath) && Files.exists(keyPath)) {
            // Load existing credentials
            String certPem = Files.readString(certPath);
            String keyPem = Files.readString(keyPath);

            return new FabricUser(caAdminName, mspId,
                    CryptoUtil.convertPemToPrivateKey(keyPem), certPem);
        } else {
            // Enroll with CA to get credentials
            Enrollment enrollment = caClient.enroll(caAdminName, caAdminPassword);

            // Save to filesystem for future use
            Files.createDirectories(certPath.getParent());
            Files.createDirectories(keyPath.getParent());
            Files.writeString(certPath, enrollment.getCert());

            // This is simplified for demo - in real system, private key handling would be different
            String privateKeyPem = encodePrivateKeyToPem(enrollment.getKey());
            Files.writeString(keyPath, privateKeyPem);

            return new FabricUser(caAdminName, mspId, enrollment);
        }
    }

    /**
     * Encode a private key to PEM format
     */
    private String encodePrivateKeyToPem(PrivateKey privateKey) {
        byte[] keyBytes = privateKey.getEncoded();
        String base64Key = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyBytes);

        return "-----BEGIN PRIVATE KEY-----\n" + base64Key + "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * Implementation of Fabric User interface for admin
     */
    private static class FabricUser implements User {
        private final String name;
        private final String mspId;
        private final Enrollment enrollment;

        public FabricUser(String name, String mspId, Enrollment enrollment) {
            this.name = name;
            this.mspId = mspId;
            this.enrollment = enrollment;
        }

        public FabricUser(String name, String mspId, java.security.PrivateKey privateKey, String certificate) {
            this.name = name;
            this.mspId = mspId;
            this.enrollment = new X509Enrollment(privateKey, certificate);
        }

        @Override
        public String getName() { return name; }

        @Override
        public Set<String> getRoles() { return Collections.emptySet(); }

        @Override
        public String getAccount() { return null; }

        @Override
        public String getAffiliation() { return null; }

        @Override
        public Enrollment getEnrollment() { return enrollment; }

        @Override
        public String getMspId() { return mspId; }
    }
}
