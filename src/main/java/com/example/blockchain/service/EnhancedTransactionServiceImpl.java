package com.example.blockchain.service;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.function.Function;

import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.Proposal;
import org.hyperledger.fabric.client.Transaction;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.example.blockchain.api.dto.TransactionDto;
import com.example.blockchain.api.dto.response.TransactionResponse;
import com.example.blockchain.exception.BlockchainException;

import lombok.extern.slf4j.Slf4j;

/**
 * Enhanced transaction service using Xipki for improved performance
 */
@Slf4j
@Service
@Primary
public class EnhancedTransactionServiceImpl implements TransactionService {

    @Autowired
    private XipkiEnhancedKeyService enhancedKeyService;

    @Autowired
    @Qualifier("gatewayBuilder")
    private Gateway.Builder gatewayBuilder;

    @Value("${fabric.msp-id}")
    private String mspId;

    @Value("${fabric.channel-name}")
    private String channelName;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${hsm.enhanced.enabled:true}")
    private boolean enhancedModeEnabled;

    @Value("${fabric.cert-dir-path}")
    private String certsDir;

    @Value("${file.cert-suffix}")
    private String certSuffix;

    @Value("${fabric.messages.submit-success}")
    private String submitSuccessMessage;

    @Value("${fabric.messages.query-success}")
    private String querySuccessMessage;

    @Value("${fabric.messages.submit-error}")
    private String submitErrorMessage;

    @Value("${fabric.messages.query-error}")
    private String queryErrorMessage;

    /**
     * Submit transaction using Xipki enhanced service
     */
    @Override
    public TransactionResponse submitTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Submitting transaction: {} for user: {} (enhanced: {})", 
                    transactionDto.getFunctionName(), userId, enhancedModeEnabled);

            if (enhancedModeEnabled) {
                return executeWithEnhancedSigner(userId, transactionDto, this::processSubmitTransaction);
            } else {
                // Fallback to standard implementation
                return executeWithStandardSigner(userId, transactionDto, this::processSubmitTransaction);
            }
        } catch (Exception e) {
            log.error("Enhanced transaction submission failed: {}", e.getMessage(), e);
            throw new BlockchainException(submitErrorMessage + ": " + e.getMessage());
        }
    }

    /**
     * Submit offline transaction using enhanced service
     */
    @Override
    public TransactionResponse submitOfflineTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Submitting offline transaction: {} for user: {} (enhanced: {})", 
                    transactionDto.getFunctionName(), userId, enhancedModeEnabled);

            if (enhancedModeEnabled) {
                return executeWithEnhancedSigner(userId, transactionDto, this::processOfflineSubmitTransaction);
            } else {
                return executeWithStandardSigner(userId, transactionDto, this::processOfflineSubmitTransaction);
            }
        } catch (Exception e) {
            log.error("Enhanced offline transaction submission failed: {}", e.getMessage(), e);
            throw new BlockchainException(submitErrorMessage + ": " + e.getMessage());
        }
    }

    /**
     * Query transaction using enhanced service
     */
    @Override
    public TransactionResponse queryTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Querying blockchain: {} for user: {} (enhanced: {})", 
                    transactionDto.getFunctionName(), userId, enhancedModeEnabled);

            if (enhancedModeEnabled) {
                return executeWithEnhancedSigner(userId, transactionDto, this::processQueryTransaction);
            } else {
                return executeWithStandardSigner(userId, transactionDto, this::processQueryTransaction);
            }
        } catch (Exception e) {
            log.error("Enhanced query failed: {}", e.getMessage(), e);
            throw new BlockchainException(queryErrorMessage + ": " + e.getMessage());
        }
    }

    /**
     * Execute with Xipki enhanced signer - optimized performance
     */
    private TransactionResponse executeWithEnhancedSigner(UUID userId, TransactionDto transactionDto,
            Function<GatewayContext, TransactionResponse> processor) throws Exception {

        long startTime = System.currentTimeMillis();
        
        // Fast key pair retrieval using enhanced service
        KeyPair keyPair = enhancedKeyService.getKeyPair(userId.toString());
        
        long keyRetrievalTime = System.currentTimeMillis();
        log.debug("Enhanced key retrieval took {} ms", (keyRetrievalTime - startTime));

        // Load certificate from filesystem
        X509Certificate certificate = getCertificateFromFilesystem(userId.toString());
        X509Identity identity = new X509Identity(mspId, certificate);

        // Create enhanced signer using Xipki
        Signer enhancedSigner = (digest) -> {
            try {
                long signStartTime = System.currentTimeMillis();
                byte[] signature = enhancedKeyService.signData(userId.toString(), digest);
                long signEndTime = System.currentTimeMillis();
                
                log.debug("Enhanced signing took {} ms", (signEndTime - signStartTime));
                return signature;
            } catch (Exception e) {
                throw new RuntimeException("Enhanced signing failed", e);
            }
        };

        try (Gateway gateway = gatewayBuilder.identity(identity).signer(enhancedSigner).connect()) {
            byte[][] args = convertArgsToBytes(transactionDto.getArguments());
            GatewayContext context = new GatewayContext(gateway, args, keyPair, transactionDto);
            
            TransactionResponse response = processor.apply(context);
            
            long totalTime = System.currentTimeMillis();
            log.info("✅ Enhanced transaction completed in {} ms", (totalTime - startTime));
            
            return response;
        }
    }

    /**
     * Fallback to standard signer for comparison/compatibility
     */
    private TransactionResponse executeWithStandardSigner(UUID userId, TransactionDto transactionDto,
            Function<GatewayContext, TransactionResponse> processor) throws Exception {
        
        log.debug("Using standard signer as fallback");
        
        // Use basic key retrieval
        KeyPair keyPair = enhancedKeyService.getKeyPair(userId.toString());
        X509Certificate certificate = getCertificateFromFilesystem(userId.toString());
        X509Identity identity = new X509Identity(mspId, certificate);

        // Standard signer
        Signer signer = (digest) -> {
            try {
                java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
                signature.initSign(keyPair.getPrivate());
                signature.update(digest);
                return signature.sign();
            } catch (Exception e) {
                throw new RuntimeException("Standard signing failed", e);
            }
        };

        try (Gateway gateway = gatewayBuilder.identity(identity).signer(signer).connect()) {
            byte[][] args = convertArgsToBytes(transactionDto.getArguments());
            GatewayContext context = new GatewayContext(gateway, args, keyPair, transactionDto);
            
            return processor.apply(context);
        }
    }

    /**
     * Process transaction submission
     */
    private TransactionResponse processSubmitTransaction(GatewayContext context) {
        try {
            // Submit transaction directly using the gateway
            byte[] result = context.gateway.getNetwork(channelName)
                    .getContract(chaincodeName)
                    .submitTransaction(context.transactionDto.getFunctionName(), context.args);

            // Build and return response
            return TransactionResponse.builder()
                    .result(new String(result, StandardCharsets.UTF_8))
                    .message(submitSuccessMessage)
                    .statusCode(0)
                    .successful(true)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Error processing enhanced transaction submission", e);
        }
    }

    /**
     * Process offline transaction submission
     */
    private TransactionResponse processOfflineSubmitTransaction(GatewayContext context) {
        try {
            Network network = context.gateway.getNetwork(channelName);
            Contract contract = network.getContract(chaincodeName);

            // Create proposal
            Proposal proposal = contract.newProposal(context.transactionDto.getFunctionName())
                    .addArguments(context.args)
                    .build();

            // Endorse the proposal
            Transaction transaction = proposal.endorse();

            // Submit the transaction
            byte[] result = transaction.submit();

            if (result != null) {
                return TransactionResponse.builder()
                        .result(new String(result, StandardCharsets.UTF_8))
                        .message(submitSuccessMessage)
                        .statusCode(0)
                        .successful(true)
                        .build();
            } else {
                throw new RuntimeException("Transaction failed - null result returned");
            }

        } catch (Exception e) {
            throw new RuntimeException("Error processing enhanced offline transaction submission", e);
        }
    }

    /**
     * Process query transaction
     */
    private TransactionResponse processQueryTransaction(GatewayContext context) {
        try {
            // Query the blockchain
            byte[] result = context.gateway.getNetwork(channelName)
                    .getContract(chaincodeName)
                    .evaluateTransaction(context.transactionDto.getFunctionName(), context.args);

            return TransactionResponse.builder()
                    .result(new String(result, StandardCharsets.UTF_8))
                    .message(querySuccessMessage)
                    .statusCode(0)
                    .successful(true)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Error processing enhanced query transaction", e);
        }
    }

    /**
     * Load certificate from filesystem
     */
    private X509Certificate getCertificateFromFilesystem(String userId) throws Exception {
        String certPath = certsDir + "/" + userId + certSuffix;
        
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Convert string arguments to byte arrays
     */
    private byte[][] convertArgsToBytes(String[] args) throws Exception {
        if (args == null) {
            return new byte[0][];
        }
        
        byte[][] result = new byte[args.length][];
        for (int i = 0; i < args.length; i++) {
            result[i] = args[i].getBytes(StandardCharsets.UTF_8);
        }
        return result;
    }

    // Context record for gateway operations
    private record GatewayContext(Gateway gateway, byte[][] args, KeyPair keyPair, TransactionDto transactionDto) {}
}
