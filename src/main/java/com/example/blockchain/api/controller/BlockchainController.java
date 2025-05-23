package com.example.blockchain.api.controller;

import com.example.blockchain.api.dto.TransactionDto;
import com.example.blockchain.api.dto.UserRegistrationDto;
import com.example.blockchain.api.dto.response.ApiResponse;
import com.example.blockchain.api.dto.response.EnrollmentResponse;
import com.example.blockchain.api.dto.response.TransactionResponse;
import com.example.blockchain.service.AdminService;
import com.example.blockchain.service.TransactionService;
import com.example.blockchain.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/blockchain")
public class BlockchainController {

    private final UserService userService;
    private final AdminService adminService;
    private final TransactionService transactionService;

    /**
     * Register a new admin user
     */
    @PostMapping("/admin/register")
    public ResponseEntity<ApiResponse<EnrollmentResponse>> registerAdmin() {
        log.info("Received request to register admin user");

        // Generate a random UUID for the admin
        UUID adminId = UUID.randomUUID();
        EnrollmentResponse response = adminService.registerAdmin(adminId);

        return ResponseEntity.ok(ApiResponse.success(response, "Admin registered successfully"));
    }

    /**
     * Register a new client user
     */
    @PostMapping("/users/register")
    public ResponseEntity<ApiResponse<EnrollmentResponse>> registerUser(@Valid @RequestBody UserRegistrationDto registrationDto) {
        log.info("Received request to register user: {}", registrationDto.getUserId());

        EnrollmentResponse response = userService.registerUser(registrationDto);

        return ResponseEntity.ok(ApiResponse.success(response, "User registered successfully"));
    }

    /**
     * Submit a transaction to the blockchain
     */
    @PostMapping("/transactions")
    public ResponseEntity<ApiResponse<TransactionResponse>> submitTransaction(
            @Valid @RequestBody TransactionDto transactionDto,
            @RequestHeader("User-ID") UUID userId) {

        log.info("Received request to submit transaction from user: {}", userId);

        TransactionResponse response = transactionService.submitTransaction(transactionDto, userId);

        return ResponseEntity.ok(ApiResponse.success(response, "Transaction submitted successfully"));
    }

    /**
     * Query the blockchain ledger
     */
    @PostMapping("/query")
    public ResponseEntity<ApiResponse<TransactionResponse>> queryTransaction(
            @Valid @RequestBody TransactionDto transactionDto,
            @RequestHeader("User-ID") UUID userId) {

        log.info("Received request to query blockchain from user: {}", userId);

        TransactionResponse response = transactionService.queryTransaction(transactionDto, userId);

        return ResponseEntity.ok(ApiResponse.success(response, "Query executed successfully"));
    }
}
