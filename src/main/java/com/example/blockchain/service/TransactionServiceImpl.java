package com.example.blockchain.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

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

            // Retrieve user certificate and private key
            KeyPair userKeyPair = getUserKeyPair(userId.toString());
            X509Certificate certificate = (X509Certificate) pkcs11KeyStore.getCertificate(userId.toString());

            // Create identity and connect to gateway
            X509Identity identity = new X509Identity(mspId, certificate);
            Gateway gateway = gatewayBuilder.identity(identity).connect();

            try {
                // Get network and contract
                Network network = gateway.getNetwork(channelName);
                Contract contract = network.getContract(chaincodeName);

                // Prepare arguments
                byte[][] args = convertArgsToBytes(transactionDto.getArguments());

                // Create and sign proposal
                Proposal proposal = contract.newProposal(transactionDto.getFunctionName())
                        .addArguments(args)
                        .build();

                byte[] proposalDigest = proposal.getDigest();
                byte[] signature = sign(proposalDigest, userKeyPair);

                // Submit signed proposal
                Proposal signedProposal = gateway.newSignedProposal(proposal.getBytes(), signature);
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
                        .message("Transaction submitted successfully")
                        .statusCode(status.getCode().getNumber())
                        .blockNumber(status.getBlockNumber())
                        .build();
            } finally {
                gateway.close();
            }
        } catch (Exception e) {
            log.error("Failed to submit transaction: {}", e.getMessage(), e);
            throw new BlockchainException("Failed to submit transaction: " + e.getMessage());
        }
    }

    @Override
    public TransactionResponse queryTransaction(TransactionDto transactionDto, UUID userId) {
        try {
            log.info("Querying blockchain: {} for user: {}", transactionDto.getFunctionName(), userId);

            // Retrieve user certificate and private key
            KeyPair userKeyPair = getUserKeyPair(userId.toString());
            X509Certificate certificate = (X509Certificate) pkcs11KeyStore.getCertificate(userId.toString());

            // Create identity and connect to gateway
            X509Identity identity = new X509Identity(mspId, certificate);
            Gateway gateway = gatewayBuilder.identity(identity).connect();

            try {
                // Get network and contract
                Network network = gateway.getNetwork(channelName);
                Contract contract = network.getContract(chaincodeName);

                // Prepare arguments
                byte[][] args = convertArgsToBytes(transactionDto.getArguments());

                // Create and sign proposal
                Proposal proposal = contract.newProposal(transactionDto.getFunctionName())
                        .addArguments(args)
                        .build();

                byte[] proposalDigest = proposal.getDigest();
                byte[] signature = sign(proposalDigest, userKeyPair);

                // Evaluate signed proposal
                Proposal signedProposal = gateway.newSignedProposal(proposal.getBytes(), signature);
                byte[] result = signedProposal.evaluate();

                // Parse and return result
                String resultStr = new String(result, StandardCharsets.UTF_8);

                return TransactionResponse.builder()
                        .transactionId(proposal.getTransactionId())
                        .successful(true)
                        .message("Query executed successfully")
                        .result(resultStr)
                        .build();
            } finally {
                gateway.close();
            }
        } catch (Exception e) {
            log.error("Failed to query blockchain: {}", e.getMessage(), e);
            throw new BlockchainException("Failed to query blockchain: " + e.getMessage());
        }
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
        java.security.Signature signature = java.security.Signature.getInstance("NONEwithECDSA", "SunPKCS11-ForFabric");
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
}
