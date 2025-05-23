package com.example.blockchain.util;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for cryptographic operations
 */
@Slf4j
@Component
public class CryptoUtil {

    @Value("${crypto.hash-algorithm:SHA-256}")
    private String hashAlgorithm;
    
    @Value("${crypto.signature-algorithm:SHA256withECDSA}")
    private String signatureAlgorithm;
    
    @Value("${crypto.ec-curve:secp256r1}")
    private String ecCurve;

    /**
     * Converts a PEM formatted certificate string to X509Certificate object
     */
    public static X509Certificate convertPemToCertificate(String certPem) throws Exception {
        // Remove PEM headers and whitespace
        String cleanPem = certPem
                .replaceAll("-+BEGIN CERTIFICATE-+|-+END CERTIFICATE-+", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(cleanPem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /**
     * Converts a PEM formatted key string to PrivateKey object
     */
    public static PrivateKey convertPemToPrivateKey(String keyPem) throws Exception {
        // Remove PEM headers and whitespace - handle multiple formats
        String cleanPem = keyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(cleanPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Try RSA first, then EC if that fails
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(keySpec);
        }
    }

    /**
     * Generate a Certificate Signing Request (CSR) from a key pair
     */
    public String generateCsr(KeyPair keyPair, String userId) throws Exception {
        // Create X500Name - in this case just the CN, but you can add more attributes
        X500Name subject = new X500Name("CN=" + userId);

        // Create PKCS10 CSR builder
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        // Create extensions generator
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        // Add Key Usage extension
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        extensionsGenerator.addExtension(Extension.keyUsage, true, keyUsage);

        // Create content signer
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        // Build the CSR
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        // Convert to PEM format
        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(str)) {
            pemWriter.writeObject(pemObject);
        }

        return str.toString();
    }

    /**
     * Generate a hash of a string using configured hash algorithm
     */
    public String sha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            byte[] hash = digest.digest(input.getBytes());

            // Convert byte array to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            log.error("Error generating {} hash: {}", hashAlgorithm, e.getMessage(), e);
            throw new RuntimeException("Could not generate hash", e);
        }
    }
}
