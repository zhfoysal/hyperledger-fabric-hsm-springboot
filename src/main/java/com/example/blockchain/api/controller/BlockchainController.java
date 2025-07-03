package com.example.blockchain.api.controller;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/blockchain")
public class BlockchainController {

    private final UserService userService;
    private final AdminService adminService;
    private final TransactionService transactionService;
    
    @Value("${api.messages.admin-register-success}")
    private String adminRegisterSuccessMessage;
    
    @Value("${api.messages.user-register-success}")
    private String userRegisterSuccessMessage;
    
    @Value("${api.messages.transaction-submit-success}")
    private String transactionSubmitSuccessMessage;
    
    @Value("${api.messages.query-success}")
    private String querySuccessMessage;

    /**
     * Register a new admin user
     */
    @PostMapping("/admin/register")
    public ResponseEntity<ApiResponse<EnrollmentResponse>> registerAdmin() {
        log.info("Received request to register admin user");

        // Generate a random UUID for the admin
        UUID adminId = UUID.randomUUID();
        EnrollmentResponse response = adminService.registerAdmin(adminId);

        return ResponseEntity.ok(ApiResponse.success(response, adminRegisterSuccessMessage));
    }

    /**
     * Register a new client user
     */
    @PostMapping("/users/register")
    public ResponseEntity<ApiResponse<EnrollmentResponse>> registerUser(@Valid @RequestBody UserRegistrationDto registrationDto) {
        log.info("Received request to register user: {}", registrationDto.getUserId());

        EnrollmentResponse response = userService.registerUser(registrationDto);

        return ResponseEntity.ok(ApiResponse.success(response, userRegisterSuccessMessage));
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

        return ResponseEntity.ok(ApiResponse.success(response, transactionSubmitSuccessMessage));
    }

    /**
     * Submit an OfflineTransaction to the blockchain
     */
    @PostMapping("/offline-transactions")
    public ResponseEntity<ApiResponse<TransactionResponse>> submitOfflineTransaction(
            @Valid @RequestBody TransactionDto transactionDto,
            @RequestHeader("User-ID") UUID userId) {

        log.info("Received request to submit transaction from user: {}", userId);

        TransactionResponse response = transactionService.submitOfflineTransaction(transactionDto, userId);

        return ResponseEntity.ok(ApiResponse.success(response, transactionSubmitSuccessMessage));
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

        return ResponseEntity.ok(ApiResponse.success(response, querySuccessMessage));
    }
}
