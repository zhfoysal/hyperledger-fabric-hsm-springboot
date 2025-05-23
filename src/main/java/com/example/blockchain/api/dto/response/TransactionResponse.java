package com.example.blockchain.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionResponse {

    /**
     * The transaction ID from the blockchain
     */
    private String transactionId;

    /**
     * Whether the transaction was successful
     */
    private boolean successful;

    /**
     * Response message
     */
    private String message;

    /**
     * Status code from the blockchain
     */
    private int statusCode;

    /**
     * Block number where the transaction was committed
     */
    private long blockNumber;

    /**
     * Result data for query transactions
     */
    private String result;
}
