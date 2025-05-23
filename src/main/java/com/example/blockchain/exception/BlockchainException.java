package com.example.blockchain.exception;

import lombok.Getter;

/**
 * Exception for blockchain-related errors
 */
@Getter
public class BlockchainException extends RuntimeException {

    private final String errorCode;

    public BlockchainException(String message) {
        super(message);
        this.errorCode = "BLOCKCHAIN_ERROR";
    }

    public BlockchainException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public BlockchainException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "BLOCKCHAIN_ERROR";
    }

    public BlockchainException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
