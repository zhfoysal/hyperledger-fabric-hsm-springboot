package com.example.blockchain.api.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDto {

    /**
     * Unique identifier for the user
     */
    @NotNull(message = "User ID is required")
    private UUID userId;

    /**
     * Optional role for the user (client or admin)
     */
    private String role;

    /**
     * Optional additional attributes for the user
     */
    private String attributes;
}
