package com.example.blockchain.service;

import com.example.blockchain.api.dto.UserRegistrationDto;
import com.example.blockchain.api.dto.response.EnrollmentResponse;
import com.example.blockchain.exception.BlockchainException;
import com.example.blockchain.util.CertificateUtil;
import com.example.blockchain.util.CryptoUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final HFCAClient caClient;
    private final AdminService adminService;

    @Value("${fabric.msp-id}")
    private String mspId;

    @Value("${ca-admin.org-name}")
    private String orgName;

    @Override
    public EnrollmentResponse registerUser(UserRegistrationDto registrationDto) {
        try {
            String userId = registrationDto.getUserId().toString();
            log.info("Registering new user: {}", userId);

            // Generate key pair for the user
            KeyPair keyPair = generateKeyPair();
            String csr = CryptoUtil.generateCsr(keyPair, userId);

            // Register the user with the CA
            String enrollmentSecret = registerUserWithCA(userId);

            // Enroll the user with the CSR
            Enrollment enrollment = enrollUser(userId, enrollmentSecret, csr, keyPair);

            // Store the private key for the user (normally would use HSM)
            storeUserCredentials(userId, keyPair, enrollment.getCert());

            // Create the enrollment response
            String bcAddress = CryptoUtil.sha256Hash(
                    CertificateUtil.getUserID(enrollment.getCert().getBytes()));

            return EnrollmentResponse.builder()
                    .userId(registrationDto.getUserId())
                    .blockchainAddress(bcAddress)
                    .certificate(enrollment.getCert())
                    .certificateSecret(enrollmentSecret)
                    .build();
        } catch (Exception e) {
            log.error("Failed to register user: {}", e.getMessage(), e);
            throw new BlockchainException("Failed to register user: " + e.getMessage());
        }
    }

    @Override
    public EnrollmentResponse reEnrollUser(UUID userId, String enrollmentSecret, String csr) {
        try {
            String userIdStr = userId.toString();
            log.info("Re-enrolling user: {}", userIdStr);

            // Re-enroll the user with the provided CSR
            Enrollment enrollment = enrollUser(userIdStr, enrollmentSecret, csr, generateKeyPair());

            // Create the enrollment response
            String bcAddress = CryptoUtil.sha256Hash(
                    CertificateUtil.getUserID(enrollment.getCert().getBytes()));

            return EnrollmentResponse.builder()
                    .userId(userId)
                    .blockchainAddress(bcAddress)
                    .certificate(enrollment.getCert())
                    .build();
        } catch (Exception e) {
            log.error("Failed to re-enroll user: {}", e.getMessage(), e);
            throw new BlockchainException("Failed to re-enroll user: " + e.getMessage());
        }
    }

    /**
     * Register a new user with the Fabric CA
     */
    private String registerUserWithCA(String userId) throws Exception {
        User admin = adminService.getCaAdmin();
        RegistrationRequest registrationRequest = new RegistrationRequest(userId, "org1.department1");
        registrationRequest.setMaxEnrollments(-1);
        return caClient.register(registrationRequest, admin);
    }

    /**
     * Enroll a user with the Fabric CA using a CSR
     */
    private Enrollment enrollUser(String userId, String secret, String csr, KeyPair keyPair) throws Exception {
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setCsr(csr);
        enrollmentRequest.setKeyPair(keyPair);
        return caClient.enroll(userId, secret, enrollmentRequest);
    }

    /**
     * Generate an EC key pair for the user
     */
    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256 curve
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Store user credentials (in a real system, private keys would go to HSM)
     * This is a simplified implementation for demonstration purposes
     */
    private void storeUserCredentials(String userId, KeyPair keyPair, String certificate) {
        // In a real implementation, you would:
        // 1. Store the certificate in a database
        // 2. Securely store the private key in an HSM or secure store

        log.info("User credentials generated for user: {} (in real app, private key would be in HSM)", userId);
    }
}
