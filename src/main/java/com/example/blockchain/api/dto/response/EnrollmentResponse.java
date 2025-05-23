package com.example.blockchain.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnrollmentResponse {

    /**
     * The UUID of the enrolled user
     */
    private UUID userId;

    /**
     * The blockchain address derived from the user's certificate
     */
    private String blockchainAddress;

    /**
     * The X.509 certificate in PEM format
     */
    private String certificate;

    /**
     * The enrollment secret (only provided during initial enrollment)
     */
    private String certificateSecret;
}
