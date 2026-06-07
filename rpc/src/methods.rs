use crate::common::RpcMethod;

pub enum ZilMethods {
    GetSmartContractInit,
    GetBalance,
    GetSmartContractSubState,
    GetNetworkId,
    GetPendingTxn,
    GetTransaction,
    CreateTransaction,
    GetTransactionStatus,
    GetLatestTxBlock,
    GetTxBlock,
    GetRecentTransactions,
    GetMinimumGasPrice,
    GetBlockchainInfo,
}

impl RpcMethod for ZilMethods {
    fn as_str(&self) -> &'static str {
        match self {
            ZilMethods::GetSmartContractInit => "GetSmartContractInit",
            ZilMethods::GetBalance => "GetBalance",
            ZilMethods::GetSmartContractSubState => "GetSmartContractSubState",
            ZilMethods::GetNetworkId => "GetNetworkId",
            ZilMethods::GetPendingTxn => "GetPendingTxn",
            ZilMethods::GetTxBlock => "GetTxBlock",
            ZilMethods::GetTransaction => "GetTransaction",
            ZilMethods::CreateTransaction => "CreateTransaction",
            ZilMethods::GetTransactionStatus => "GetTransactionStatus",
            ZilMethods::GetLatestTxBlock => "GetLatestTxBlock",
            ZilMethods::GetRecentTransactions => "GetRecentTransactions",
            ZilMethods::GetMinimumGasPrice => "GetMinimumGasPrice",
            ZilMethods::GetBlockchainInfo => "GetBlockchainInfo",
        }
    }
}
impl std::fmt::Display for ZilMethods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub enum EvmMethods {
    // State Methods
    GetBalance,
    GetStorageAt,
    GetTransactionCount,
    GetBlockTransactionCountByHash,
    GetBlockTransactionCountByNumber,
    GetCode,
    Call,
    EstimateGas,

    // Block Methods
    BlockNumber,
    GetBlockByHash,
    GetBlockByNumber,
    GetBlockReceipts,

    // Transaction Methods
    SendRawTransaction,
    GetTransactionByHash,
    GetTransactionByBlockHashAndIndex,
    GetTransactionByBlockNumberAndIndex,
    GetTransactionReceipt,

    // Account Methods
    Accounts,
    GetProof,

    // Chain State
    ChainId,
    NetworkVersion,
    Syncing,
    GasPrice,
    MaxPriorityFeePerGas,
    FeeHistory,
    BlobBaseFee,

    // Filter Methods
    NewFilter,
    NewBlockFilter,
    NewPendingTransactionFilter,
    UninstallFilter,
    GetFilterChanges,
    GetFilterLogs,
    GetLogs,

    // Contract Methods
    Sign,
    SignTransaction,

    // Debug and Trace
    DebugTraceTransaction,
    DebugTraceCall,
    TraceBlock,
    TraceTransaction,

    // Mining Methods
    Mining,
    Hashrate,
    GetWork,
    SubmitWork,
    SubmitHashrate,
}

impl RpcMethod for EvmMethods {
    fn as_str(&self) -> &'static str {
        match self {
            // State Methods
            Self::GetBalance => "eth_getBalance",
            Self::GetStorageAt => "eth_getStorageAt",
            Self::GetTransactionCount => "eth_getTransactionCount",
            Self::GetBlockTransactionCountByHash => "eth_getBlockTransactionCountByHash",
            Self::GetBlockTransactionCountByNumber => "eth_getBlockTransactionCountByNumber",
            Self::GetCode => "eth_getCode",
            Self::Call => "eth_call",
            Self::EstimateGas => "eth_estimateGas",

            // Block Methods
            Self::BlockNumber => "eth_blockNumber",
            Self::GetBlockByHash => "eth_getBlockByHash",
            Self::GetBlockByNumber => "eth_getBlockByNumber",
            Self::GetBlockReceipts => "eth_getBlockReceipts",

            // Transaction Methods
            Self::SendRawTransaction => "eth_sendRawTransaction",
            Self::GetTransactionByHash => "eth_getTransactionByHash",
            Self::GetTransactionByBlockHashAndIndex => "eth_getTransactionByBlockHashAndIndex",
            Self::GetTransactionByBlockNumberAndIndex => "eth_getTransactionByBlockNumberAndIndex",
            Self::GetTransactionReceipt => "eth_getTransactionReceipt",

            // Account Methods
            Self::Accounts => "eth_accounts",
            Self::GetProof => "eth_getProof",

            // Chain State
            Self::ChainId => "eth_chainId",
            Self::NetworkVersion => "net_version",
            Self::Syncing => "eth_syncing",
            Self::GasPrice => "eth_gasPrice",
            Self::MaxPriorityFeePerGas => "eth_maxPriorityFeePerGas",
            Self::FeeHistory => "eth_feeHistory",
            Self::BlobBaseFee => "eth_blobBaseFee",

            // Filter Methods
            Self::NewFilter => "eth_newFilter",
            Self::NewBlockFilter => "eth_newBlockFilter",
            Self::NewPendingTransactionFilter => "eth_newPendingTransactionFilter",
            Self::UninstallFilter => "eth_uninstallFilter",
            Self::GetFilterChanges => "eth_getFilterChanges",
            Self::GetFilterLogs => "eth_getFilterLogs",
            Self::GetLogs => "eth_getLogs",

            // Contract Methods
            Self::Sign => "eth_sign",
            Self::SignTransaction => "eth_signTransaction",

            // Debug and Trace
            Self::DebugTraceTransaction => "debug_traceTransaction",
            Self::DebugTraceCall => "debug_traceCall",
            Self::TraceBlock => "trace_block",
            Self::TraceTransaction => "trace_transaction",

            // Mining Methods
            Self::Mining => "eth_mining",
            Self::Hashrate => "eth_hashrate",
            Self::GetWork => "eth_getWork",
            Self::SubmitWork => "eth_submitWork",
            Self::SubmitHashrate => "eth_submitHashrate",
        }
    }
}

impl std::fmt::Display for EvmMethods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub enum SolanaMethod {
    GetBalance,
    GetSlot,
    GetLatestBlockhash,
    SendTransaction,
    GetTransaction,
    GetTokenAccountsByOwner,
    GetAccountInfo,
    GetMultipleAccounts,
    GetFeeForMessage,
}

impl RpcMethod for SolanaMethod {
    fn as_str(&self) -> &'static str {
        match self {
            Self::GetBalance => "getBalance",
            Self::GetSlot => "getSlot",
            Self::GetLatestBlockhash => "getLatestBlockhash",
            Self::SendTransaction => "sendTransaction",
            Self::GetTransaction => "getTransaction",
            Self::GetTokenAccountsByOwner => "getTokenAccountsByOwner",
            Self::GetAccountInfo => "getAccountInfo",
            Self::GetMultipleAccounts => "getMultipleAccounts",
            Self::GetFeeForMessage => "getFeeForMessage",
        }
    }
}

impl std::fmt::Display for SolanaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_names() {
        assert_eq!(EvmMethods::GetBalance.as_str(), "eth_getBalance");
        assert_eq!(EvmMethods::Call.as_str(), "eth_call");
        assert_eq!(EvmMethods::ChainId.as_str(), "eth_chainId");
        assert_eq!(
            EvmMethods::DebugTraceTransaction.as_str(),
            "debug_traceTransaction"
        );
    }

    #[test]
    fn test_display_implementation() {
        assert_eq!(EvmMethods::GetBalance.to_string(), "eth_getBalance");
        assert_eq!(format!("{}", EvmMethods::Call), "eth_call");
    }
}
