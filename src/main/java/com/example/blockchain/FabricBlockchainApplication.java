package com.example.blockchain;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class FabricBlockchainApplication {

    public static void main(String[] args) {
        // Add BouncyCastle as a security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SpringApplication.run(FabricBlockchainApplication.class, args);
    }
}
