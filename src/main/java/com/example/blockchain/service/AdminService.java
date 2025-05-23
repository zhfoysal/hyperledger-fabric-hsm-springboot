package com.example.blockchain.service;

import com.example.blockchain.api.dto.response.EnrollmentResponse;
import org.hyperledger.fabric.sdk.User;

import java.util.UUID;

public interface AdminService {

    /**
     * Register and enroll a new admin user on the blockchain network
     * @param adminId UUID of the admin to register
     * @return EnrollmentResponse containing credentials and blockchain address
     */
    EnrollmentResponse registerAdmin(UUID adminId);

    /**
     * Get the CA admin user required for registering new users
     * @return Fabric User representing the CA admin
     */
    User getCaAdmin();
}
