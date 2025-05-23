package com.example.blockchain.service;

import com.example.blockchain.api.dto.UserRegistrationDto;
import com.example.blockchain.api.dto.response.EnrollmentResponse;

import java.util.UUID;

public interface UserService {
    /**
     * Register and enroll a new client user
     * @param registrationDto User registration data
     * @return Enrollment response containing credentials
     */
    EnrollmentResponse registerUser(UserRegistrationDto registrationDto);

    /**
     * Re-enroll an existing user with new credentials
     * @param userId User identifier
     * @param enrollmentSecret Enrollment secret
     * @param csr Certificate signing request
     * @return Enrollment response containing credentials
     */
    EnrollmentResponse reEnrollUser(UUID userId, String enrollmentSecret, String csr);
}
