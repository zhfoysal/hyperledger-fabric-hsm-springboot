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

    @Override
    public TransactionResponse submitTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Submitting transaction: {} for user: {}", transactionDto.getFunctionName(), userId);

            return executeWithGateway(userId, transactionDto, this::processSubmitTransaction);
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

    /**
     * Common method to execute operations with gateway setup
     */
    private TransactionResponse executeWithGateway(UUID userId, TransactionDto transactionDto,
            Function<GatewayContext, TransactionResponse> processor) throws Exception {
        // Retrieve user certificate and private key
        KeyPair userKeyPair = getUserKeyPair(userId.toString());
        X509Certificate certificate = (X509Certificate) pkcs11KeyStore.getCertificate(userId.toString());

        // Create identity and connect to gateway
        X509Identity identity = new X509Identity(mspId, certificate);

        try (Gateway gateway = gatewayBuilder.identity(identity).connect()) {
            // Get network and contract
            Network network = gateway.getNetwork(channelName);
            Contract contract = network.getContract(chaincodeName);

            // Prepare arguments
            byte[][] args = convertArgsToBytes(transactionDto.getArguments());

            // Create proposal
            Proposal proposal = contract.newProposal(transactionDto.getFunctionName())
                    .addArguments(args)
                    .build();

            GatewayContext context = new GatewayContext(gateway, proposal, userKeyPair, transactionDto);

            return processor.apply(context);
        }
    }

    /**
     * Process a transaction submission
     */
    private TransactionResponse processSubmitTransaction(GatewayContext context) {
        try {
            Proposal proposal = context.proposal;
            Gateway gateway = context.gateway;
            KeyPair userKeyPair = context.userKeyPair;

            // Sign and submit proposal
            Proposal signedProposal = createSignedProposal(proposal, gateway, userKeyPair);
            Transaction transaction = signedProposal.endorse();

            // Sign and submit transaction
            byte[] transactionDigest = transaction.getDigest();
            byte[] transactionSignature = sign(transactionDigest, userKeyPair);

            Transaction signedTransaction = gateway.newSignedTransaction(
                    transaction.getBytes(), transactionSignature);

            // Submit transaction and get commit status
            Commit commit = signedTransaction.submitAsync();
            byte[] commitDigest = commit.getDigest();
            byte[] commitSignature = sign(commitDigest, userKeyPair);

            Commit signedCommit = gateway.newSignedCommit(commit.getBytes(), commitSignature);
            Status status = signedCommit.getStatus();

            // Build response
            return TransactionResponse.builder()
                    .transactionId(proposal.getTransactionId())
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
     * Process a transaction query
     */
    private TransactionResponse processQueryTransaction(GatewayContext context) {
        try {
            Proposal proposal = context.proposal;
            Gateway gateway = context.gateway;
            KeyPair userKeyPair = context.userKeyPair;

            // Sign proposal
            Proposal signedProposal = createSignedProposal(proposal, gateway, userKeyPair);
            byte[] result = signedProposal.evaluate();

            // Parse and return result
            String resultStr = new String(result, StandardCharsets.UTF_8);

            return TransactionResponse.builder()
                    .transactionId(proposal.getTransactionId())
                    .successful(true)
                    .message(querySuccessMessage)
                    .result(resultStr)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Error processing transaction query", e);
        }
    }

    /**
     * Create a signed proposal from an unsigned one
     */
    private Proposal createSignedProposal(Proposal proposal, Gateway gateway, KeyPair userKeyPair) throws Exception {
        byte[] proposalDigest = proposal.getDigest();
        byte[] signature = sign(proposalDigest, userKeyPair);
        return gateway.newSignedProposal(proposal.getBytes(), signature);
    }

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
    private byte[] sign(byte[] digest, KeyPair keyPair) throws Exception {
        // Get curve parameters from public key
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        BigInteger curveN = ecPublicKey.getParams().getOrder();
        BigInteger halfCurveN = curveN.divide(BigInteger.valueOf(2));

        // Sign using PKCS11 provider
        java.security.Signature signature = java.security.Signature.getInstance(signatureAlgorithm, signatureProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(digest);
        byte[] rawSignature = signature.sign();

        // Parse and normalize signature
        FabricUtil.ECSignature ecSignature = FabricUtil.ECSignature.fromBytes(rawSignature);

        // Prevent signature malleability by keeping s in the lower half of curve order
        BigInteger s = ecSignature.s().getValue();
        if (s.compareTo(halfCurveN) > 0) {
            s = curveN.subtract(s);
            ecSignature = new FabricUtil.ECSignature(ecSignature.r(), new org.bouncycastle.asn1.ASN1Integer(s));
        }

        return ecSignature.getBytes();
    }

    /**
     * Context class to hold gateway-related objects
     */
    private record GatewayContext(Gateway gateway, Proposal proposal, KeyPair userKeyPair, TransactionDto transactionDto) {
    }
}
