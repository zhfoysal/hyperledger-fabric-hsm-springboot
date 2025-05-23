package com.example.blockchain.config;

import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Hash;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Configuration for Hyperledger Fabric network connections
 */
@Slf4j
@Configuration
public class FabricConfig {

    // Network configuration properties
    @Value("${fabric.peer-endpoint}")
    private String peerEndpoint;

    @Value("${fabric.ca-server-endpoint}")
    private String caServerEndpoint;

    @Value("${fabric.override-auth}")
    private String overrideAuth;

    // File paths
    @Value("${fabric.crypto-path}")
    private String cryptoPath;

    @Value("${fabric.tls-cert-path}")
    private String tlsCertPath;

    // Timeout configurations
    @Value("${fabric.timeout.evaluate}")
    private int evaluateTimeoutSeconds;

    @Value("${fabric.timeout.endorse}")
    private int endorseTimeoutSeconds;

    @Value("${fabric.timeout.submit}")
    private int submitTimeoutSeconds;

    @Value("${fabric.timeout.commit}")
    private int commitTimeoutSeconds;

    /**
     * Creates and configures an HFCAClient for interacting with the Fabric CA
     */
    @Bean
    public HFCAClient caClient() throws Exception {
        Properties properties = new Properties();
        properties.put("pemFile", getTlsCertificatePath().toString());
        properties.put("allowAllHostNames", "true");

        HFCAClient caClient = HFCAClient.createNewInstance(caServerEndpoint, properties);
        caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        log.info("Successfully created HFCAClient connected to {}", caServerEndpoint);
        return caClient;
    }

    /**
     * Creates a Gateway builder configured with network connection parameters
     */
    @Bean
    @Qualifier("gatewayBuilder")
    public Gateway.Builder gatewayBuilder() throws Exception {
        ManagedChannel channel = createGrpcConnection();

        Gateway.Builder builder = Gateway.newInstance()
                .hash(Hash.SHA256)
                .connection(channel)
                .evaluateOptions(options -> options.withDeadlineAfter(evaluateTimeoutSeconds, TimeUnit.SECONDS))
                .endorseOptions(options -> options.withDeadlineAfter(endorseTimeoutSeconds, TimeUnit.SECONDS))
                .submitOptions(options -> options.withDeadlineAfter(submitTimeoutSeconds, TimeUnit.SECONDS))
                .commitStatusOptions(options -> options.withDeadlineAfter(commitTimeoutSeconds, TimeUnit.SECONDS));

        log.info("Successfully configured Gateway builder");
        return builder;
    }

    /**
     * Creates a new gRPC connection to the Fabric peer with TLS
     */
    private ManagedChannel createGrpcConnection() throws Exception {
        try {
            TlsChannelCredentials credentials = (TlsChannelCredentials) TlsChannelCredentials.newBuilder()
                    .trustManager(getTlsCertificatePath().toFile())
                    .build();

            ManagedChannel channel = Grpc.newChannelBuilder(peerEndpoint, credentials)
                    .overrideAuthority(overrideAuth)
                    .build();

            log.info("Successfully created gRPC channel to {}", peerEndpoint);
            return channel;
        } catch (Exception e) {
            log.error("Failed to create gRPC connection: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create gRPC connection to Fabric network", e);
        }
    }

    /**
     * Helper method to resolve the TLS certificate path
     */
    private Path getTlsCertificatePath() {
        if (tlsCertPath.startsWith("/")) {
            return Paths.get(tlsCertPath);
        }
        return Paths.get(cryptoPath).resolve(tlsCertPath);
    }
}
