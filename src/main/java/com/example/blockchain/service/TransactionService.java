package com.example.blockchain.service;

import java.util.UUID;

import com.example.blockchain.api.dto.TransactionDto;
import com.example.blockchain.api.dto.response.TransactionResponse;

public interface TransactionService {

    /**
     * Submit a transaction to the blockchain network
     *
     * @param transactionDto Transaction details including function name and arguments
     * @param userId The ID of the user submitting the transaction
     * @return Transaction response with results and status
     */
    TransactionResponse submitTransaction(TransactionDto transactionDto, UUID userId);

    /**
     * Submit an OfflineTransaction to the blockchain network
     *
     * @param transactionDto Transaction details including function name and arguments
     * @param userId The ID of the user submitting the transaction
     * @return Transaction response with results and status
     */
    TransactionResponse submitOfflineTransaction(TransactionDto transactionDto, UUID userId);

    /**
     * Query the blockchain ledger without submitting a transaction
     *
     * @param transactionDto Transaction details including function name and arguments
     * @param userId The ID of the user performing the query
     * @return Transaction response with query results
     */
    TransactionResponse queryTransaction(TransactionDto transactionDto, UUID userId);
}
