package com.example.blockchain.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Utility class for certificate management and processing
 */
@Slf4j
@Component
public class CertificateUtil {

    /**
     * Formats a Distinguished Name (DN) according to Fabric's requirements
     */
    public static String formatDN(X500Principal dn) {
        String dnString = dn.getName(X500Principal.RFC2253);
        String[] attributes = dnString.split(",");
        StringBuilder formatted = new StringBuilder();

        for (String attribute : attributes) {
            String[] parts = attribute.trim().split("=", 2);
            if (parts.length == 2) {
                String shortName = parts[0];
                String value = parts[1].replace("/", "\\/");
                formatted.append("/").append(shortName).append("=").append(value);
            }
        }

        return formatted.toString();
    }

    /**
     * Extracts a user ID from a certificate byte array
     * This ID format is compatible with Fabric's identity requirements
     */
    public static String getUserID(byte[] certificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate));

            String subjectDN = formatDN(cert.getSubjectX500Principal());
            String issuerDN = formatDN(cert.getIssuerX500Principal());

            String id = "x509::" + subjectDN + "::" + issuerDN;

            String[] idParts = id.split("::");
            List<String> idPartsSubject = new ArrayList<>(Arrays.asList(idParts[1].split("/")));
            List<String> idPartsIssuer = new ArrayList<>(Arrays.asList(idParts[2].split("/")));

            Collections.reverse(idPartsSubject);

            // Reorganize subject parts as per Fabric requirements
            List<String> tempList = new ArrayList<>();
            if (!idPartsSubject.isEmpty()) {
                tempList.add(idPartsSubject.remove(0));
            }

            List<String> nextThree = new ArrayList<>();
            for (int i = 0; i < Math.min(3, idPartsSubject.size()); i++) {
                nextThree.add(idPartsSubject.remove(0));
            }
            Collections.reverse(nextThree);
            tempList.addAll(nextThree);
            Collections.reverse(tempList);

            idPartsSubject = tempList;

            // Build formatted ID string
            StringBuilder ID = new StringBuilder("x509::");
            for (int i = 0; i < idPartsSubject.size(); i++) {
                if (idPartsSubject.get(i).isEmpty()) continue;
                if (ID.length() == 6) {
                    ID.append(idPartsSubject.get(i)).append(",");
                } else {
                    ID.append(idPartsSubject.get(i));
                }
                if (i > 0 && i < idPartsSubject.size() - 1) {
                    ID.append("+");
                }
            }
            ID.append("::");

            for (int i = 0; i < idPartsIssuer.size(); i++) {
                if (idPartsIssuer.get(i).isEmpty()) continue;
                ID.append(idPartsIssuer.get(i));
                if (i < idPartsIssuer.size() - 1) {
                    ID.append(",");
                }
            }

            return Base64.getEncoder().encodeToString(ID.toString().getBytes());

        } catch (Exception e) {
            log.error("Error extracting user ID from certificate: {}", e.getMessage(), e);
            return null;
        }
    }
}
