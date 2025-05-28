package com.example.blockchain.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;
import java.util.function.Function;

import org.hyperledger.fabric.client.Commit;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.Proposal;
import org.hyperledger.fabric.client.Status;
import org.hyperledger.fabric.client.Transaction;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.blockchain.api.dto.TransactionDto;
import com.example.blockchain.api.dto.response.TransactionResponse;
import com.example.blockchain.exception.BlockchainException;
import com.example.blockchain.util.FabricUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class TransactionServiceImpl implements TransactionService {

    private final Gateway.Builder gatewayBuilder;
    private final KeyStore pkcs11KeyStore;

    @Value("${fabric.msp-id}")
    private String mspId;

    @Value("${fabric.channel-name}")
    private String channelName;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${hsm.pin}")
    private String hsmPin;

    @Value("${hsm.signature.algorithm}")
    private String signatureAlgorithm;

    @Value("${hsm.signature.provider}")
    private String signatureProvider;

    @Value("${fabric.messages.submit-success}")
    private String submitSuccessMessage;

    @Value("${fabric.messages.query-success}")
    private String querySuccessMessage;

    @Value("${fabric.messages.submit-error}")
    private String submitErrorMessage;

    @Value("${fabric.messages.query-error}")
    private String queryErrorMessage;

    public TransactionServiceImpl(
            @Qualifier("gatewayBuilder") Gateway.Builder gatewayBuilder,
            @Qualifier("pkcs11KeyStore") KeyStore pkcs11KeyStore) {
        this.gatewayBuilder = gatewayBuilder;
        this.pkcs11KeyStore = pkcs11KeyStore;
    }

    // ============= PUBLIC API METHODS =============

    @Override
    public TransactionResponse submitTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Submitting transaction: {} for user: {}", transactionDto.getFunctionName(), userId);
            return executeWithGatewayUsingSigner(userId, transactionDto, this::processSubmitTransaction);
        } catch (Exception e) {
            log.error("{}: {}", submitErrorMessage, e.getMessage(), e);
            throw new BlockchainException(submitErrorMessage + ": " + e.getMessage());
        }
    }

    @Override
    public TransactionResponse submitOfflineTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Submitting transaction: {} for user: {}", transactionDto.getFunctionName(), userId);
            return executeWithGateway(userId, transactionDto, this::processOfflineSubmitTransaction);
        } catch (Exception e) {
            log.error("{}: {}", submitErrorMessage, e.getMessage(), e);
            throw new BlockchainException(submitErrorMessage + ": " + e.getMessage());
        }
    }

    @Override
    public TransactionResponse queryTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Querying blockchain: {} for user: {}", transactionDto.getFunctionName(), userId);
            return executeWithGateway(userId, transactionDto, this::processQueryTransaction);
        } catch (Exception e) {
            log.error("{}: {}", queryErrorMessage, e.getMessage(), e);
            throw new BlockchainException(queryErrorMessage + ": " + e.getMessage());
        }
    }

    // ============= GATEWAY EXECUTION METHODS =============

    /**
     * Common method to extract user identity information
     */
    private UserIdentity getUserIdentity(UUID userId) throws Exception {
        KeyPair userKeyPair = getUserKeyPair(userId.toString());
        X509Certificate certificate = (X509Certificate) pkcs11KeyStore.getCertificate(userId.toString());
        X509Identity identity = new X509Identity(mspId, certificate);
        return new UserIdentity(userKeyPair, certificate, identity);
    }

    /**
     * Common method to execute operations with gateway setup using identity only
     */
    private TransactionResponse executeWithGateway(UUID userId, TransactionDto transactionDto,
            Function<GatewayOfflineContext, TransactionResponse> processor) throws Exception {
        UserIdentity userIdentity = getUserIdentity(userId);

        try (Gateway gateway = gatewayBuilder.identity(userIdentity.identity()).connect()) {
            Network network = gateway.getNetwork(channelName);
            Contract contract = network.getContract(chaincodeName);
            byte[][] args = convertArgsToBytes(transactionDto.getArguments());

            Proposal proposal = contract.newProposal(transactionDto.getFunctionName())
                    .addArguments(args)
                    .build();

            GatewayOfflineContext context = new GatewayOfflineContext(gateway, proposal, userIdentity.keyPair(), transactionDto);
            return processor.apply(context);
        }
    }

    /**
     * Common method to execute operations with gateway setup using custom signer
     */
    private TransactionResponse executeWithGatewayUsingSigner(UUID userId, TransactionDto transactionDto, Function<GatewayContext, TransactionResponse> processor) throws Exception {
        UserIdentity userIdentity = getUserIdentity(userId);

        Signer signer = (digest) -> {
            try {
                return signWithHsm(digest, userIdentity.keyPair());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        try (Gateway gateway = gatewayBuilder.identity(userIdentity.identity()).signer(signer).connect()) {
            byte[][] args = convertArgsToBytes(transactionDto.getArguments());
            GatewayContext context = new GatewayContext(gateway, args, userIdentity.keyPair(), transactionDto);
            return processor.apply(context);
        }
    }

    // ============= TRANSACTION PROCESSING METHODS =============

    /**
     * Process a transaction submission with offline signing
     */
    private TransactionResponse processOfflineSubmitTransaction(GatewayOfflineContext context) {
        try {
            // Sign and endorse proposal
            Proposal signedProposal = createSignedProposal(context.proposal, context.gateway, context.userKeyPair);
            Transaction transaction = signedProposal.endorse();

            // Sign and submit transaction
            Transaction signedTransaction = createSignedTransaction(transaction, context.gateway, context.userKeyPair);

            // Submit transaction and get commit status
            Commit commit = signedTransaction.submitAsync();
            Commit signedCommit = createSignedCommit(commit, context.gateway, context.userKeyPair);
            Status status = signedCommit.getStatus();

            // Build and return response
            return TransactionResponse.builder()
                    .transactionId(context.proposal.getTransactionId())
                    .successful(status.isSuccessful())
                    .message(submitSuccessMessage)
                    .statusCode(status.getCode().getNumber())
                    .blockNumber(status.getBlockNumber())
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Error processing transaction submission", e);
        }
    }

    /**
     * Create a signed transaction from an unsigned one
     */
    private Transaction createSignedTransaction(Transaction transaction, Gateway gateway, KeyPair userKeyPair) throws Exception {
        byte[] transactionDigest = transaction.getDigest();
        byte[] transactionSignature = signWithHsm(transactionDigest, userKeyPair);
        return gateway.newSignedTransaction(transaction.getBytes(), transactionSignature);
    }

    /**
     * Create a signed commit from an unsigned one
     */
    private Commit createSignedCommit(Commit commit, Gateway gateway, KeyPair userKeyPair) throws Exception {
        byte[] commitDigest = commit.getDigest();
        byte[] commitSignature = signWithHsm(commitDigest, userKeyPair);
        return gateway.newSignedCommit(commit.getBytes(), commitSignature);
    }


    /**
     * Process a transaction submission using a gateway signer
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
            throw new RuntimeException("Error processing transaction submission", e);
        }
    }

    /**
     * Process a transaction query
     */
    private TransactionResponse processQueryTransaction(GatewayOfflineContext context) {
        try {
            // Sign proposal and evaluate
            Proposal signedProposal = createSignedProposal(context.proposal, context.gateway, context.userKeyPair);
            byte[] result = signedProposal.evaluate();

            // Build and return response
            return TransactionResponse.builder()
                    .transactionId(context.proposal.getTransactionId())
                    .successful(true)
                    .message(querySuccessMessage)
                    .result(new String(result, StandardCharsets.UTF_8))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Error processing transaction query", e);
        }
    }

    // ============= SIGNATURE AND CRYPTO UTILITIES =============

    /**
     * Create a signed proposal from an unsigned one
     */
    private Proposal createSignedProposal(Proposal proposal, Gateway gateway, KeyPair userKeyPair) throws Exception {
        byte[] proposalDigest = proposal.getDigest();
        byte[] signature = signWithHsm(proposalDigest, userKeyPair);
        return gateway.newSignedProposal(proposal.getBytes(), signature);
    }

    // ============= UTILITY METHODS =============

    /**
     * Retrieve user's KeyPair from HSM
     */
    private KeyPair getUserKeyPair(String userId) throws Exception {
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) pkcs11KeyStore.getEntry(
                userId, new KeyStore.PasswordProtection(hsmPin.toCharArray()));
        PrivateKey privateKey = keyEntry.getPrivateKey();
        java.security.cert.Certificate cert = keyEntry.getCertificate();
        return new KeyPair(cert.getPublicKey(), privateKey);
    }

    /**
     * Convert string arguments to byte arrays
     */
    private byte[][] convertArgsToBytes(String[] args) throws Exception {
        byte[][] result = new byte[args.length][];
        for (int i = 0; i < args.length; i++) {
            result[i] = FabricUtil.objectToBytes(args[i]);
        }
        return result;
    }

    /**
     * Sign a digest with the user's private key
     */
    private byte[] signWithHsm(byte[] digest, KeyPair keyPair) throws Exception {
        // Sign using PKCS11 provider
        java.security.Signature signature = java.security.Signature.getInstance(signatureAlgorithm, signatureProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(digest);
        byte[] rawSignature = signature.sign();

        // Parse and normalize signature to prevent malleability
        return normalizeSignature(rawSignature, keyPair);
    }

    /**
     * Normalize ECDSA signature to prevent signature malleability
     */
    private byte[] normalizeSignature(byte[] rawSignature, KeyPair keyPair) throws Exception {
        // Get curve parameters from the public key
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        BigInteger curveN = ecPublicKey.getParams().getOrder();
        BigInteger halfCurveN = curveN.divide(BigInteger.valueOf(2));

        // Parse signature
        FabricUtil.ECSignature ecSignature = FabricUtil.ECSignature.fromBytes(rawSignature);

        // Prevent signature malleability by keeping s in the lower half of the curve order
        BigInteger s = ecSignature.s().getValue();
        if (s.compareTo(halfCurveN) > 0) {
            s = curveN.subtract(s);
            ecSignature = new FabricUtil.ECSignature(ecSignature.r(), new org.bouncycastle.asn1.ASN1Integer(s));
        }

        return ecSignature.getBytes();
    }

    // ============= CONTEXT RECORDS =============

    /**
     * Context class to hold gateway-related objects
     */
    private record GatewayOfflineContext(Gateway gateway, Proposal proposal, KeyPair userKeyPair, TransactionDto transactionDto) {
    }

    /**
     * Context class to hold offline-gateway-related objects
     */
    private record GatewayContext(Gateway gateway, byte[][] args, KeyPair userKeyPair, TransactionDto transactionDto) {
    }

    /**
     * Record to hold user identity information
     */
    private record UserIdentity(KeyPair keyPair, X509Certificate certificate, X509Identity identity) {
    }

}
