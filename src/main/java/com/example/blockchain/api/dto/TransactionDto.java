package com.example.blockchain.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionDto {

    /**
     * The name of the chaincode function to invoke
     */
    @NotBlank(message = "Function name is required")
    private String functionName;

    /**
     * Array of string arguments to pass to the function
     */
    @NotEmpty(message = "At least one argument is required")
    private String[] arguments;

    /**
     * Optional transaction type (invoke or query)
     */
    private String transactionType;
}
