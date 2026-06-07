mod responses;

use crate::Result;
use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use alloy::primitives::U256;
use async_trait::async_trait;
use base64::Engine;
use errors::network::NetworkErrors;
use history::status::TransactionStatus;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::solana_tx::{build_sol_transfer_message, build_versioned_message_from_instructions};
use proto::tx::{TransactionReceipt, TransactionRequest};
use responses::{
    AccountInfoValue, BlockhashValue, MetaplexMetadata, RawAccountValue, SolanaAccountInfo,
    SolanaGetTransactionResult, SolanaValueResponse, TokenAccountEntry, extract_token2022_metadata,
};
use rpc::common::JsonRPC;
use rpc::methods::SolanaMethod;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::{ErrorRes, ResultRes};
use serde_json::{Value, json};
use solana_address_lookup_table_interface::state::AddressLookupTable;
use solana_instruction::Instruction;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use token::ft::FToken;

const SOLANA_BASE_FEE_LAMPORTS: u64 = 5000;
const METAPLEX_PROGRAM_ID: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const METAPLEX_METADATA_SEED: &[u8] = b"metadata";
const SOLANA_BLOCK_TIME_SECS: u64 = 1;
const SOLANA_TX_PENDING_TIMEOUT_SECS: u64 = 600;
const SOLANA_TOKEN_LOGO_URL: &str =
    "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet";

#[derive(Debug, Clone, Copy)]
pub struct SolanaMessageBuild<'a> {
    pub payer: &'a Pubkey,
    pub instructions: &'a [Instruction],
    pub lookup_table_addresses: &'a [Pubkey],
}

#[async_trait]
pub trait SolanaOperations {
    async fn solana_get_current_block_number(&self) -> Result<u64>;
    async fn solana_estimate_block_time(&self) -> Result<u64>;
    async fn solana_get_latest_blockhash(&self) -> Result<String>;
    async fn solana_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams>;
    async fn solana_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn solana_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn solana_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn solana_get_fee_for_message(&self, message: &[u8]) -> Result<u64>;
    async fn solana_build_message(&self, params: SolanaMessageBuild<'_>) -> Result<Vec<u8>>;
    async fn solana_check_account_health(&self, address: &str) -> Result<(u64, String)>;
    async fn solana_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken>;
}

#[async_trait]
impl SolanaOperations for NetworkProvider {
    async fn solana_get_current_block_number(&self) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(json!([]), SolanaMethod::GetSlot);
        let res: ResultRes<u64> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        res.result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))
    }

    async fn solana_estimate_block_time(&self) -> Result<u64> {
        Ok(SOLANA_BLOCK_TIME_SECS)
    }

    async fn solana_get_latest_blockhash(&self) -> Result<String> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([{"commitment": "finalized"}]),
            SolanaMethod::GetLatestBlockhash,
        );
        let res: ResultRes<SolanaValueResponse<BlockhashValue>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        Ok(value.value.blockhash)
    }

    async fn solana_get_fee_for_message(&self, message: &[u8]) -> Result<u64> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(message);
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([encoded, {"commitment": "confirmed"}]),
            SolanaMethod::GetFeeForMessage,
        );
        let res: ResultRes<SolanaValueResponse<Option<u64>>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        value
            .value
            .ok_or_else(|| NetworkErrors::RPCError("blockhash expired".into()))
    }

    async fn solana_build_message(&self, params: SolanaMessageBuild<'_>) -> Result<Vec<u8>> {
        let blockhash_str = self.solana_get_latest_blockhash().await?;
        let blockhash: [u8; 32] = bs58::decode(&blockhash_str)
            .into_vec()
            .map_err(|error| NetworkErrors::RPCError(error.to_string()))?
            .try_into()
            .map_err(|_| NetworkErrors::RPCError("blockhash must be 32 bytes".into()))?;

        let lookup_tables = if params.lookup_table_addresses.is_empty() {
            Vec::with_capacity(0)
        } else {
            self.solana_get_lookup_table_accounts(params.lookup_table_addresses)
                .await?
        };

        build_versioned_message_from_instructions(
            params.instructions,
            params.payer,
            &blockhash,
            &lookup_tables,
        )
        .map_err(NetworkErrors::RPCError)
    }

    async fn solana_check_account_health(&self, address: &str) -> Result<(u64, String)> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([address, {"encoding": "base64"}]),
            SolanaMethod::GetAccountInfo,
        );
        let res: ResultRes<SolanaValueResponse<Option<SolanaAccountInfo>>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        let info = value.value.ok_or_else(|| {
            NetworkErrors::RPCError(format!("Account {address} not found on-chain"))
        })?;

        Ok((info.space, info.owner))
    }

    async fn solana_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams> {
        let fee = if let TransactionRequest::Solana((sol_tx, _)) = tx {
            let message = if sol_tx.message.is_empty() {
                let Address::Ed25519Solana(pk) = sender else {
                    return Ok(RequiredTxParams {
                        gas_price: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        max_priority_fee: U256::ZERO,
                        fee_history: GasFeeHistory::default(),
                        tx_estimate_gas: U256::from(1u64),
                        blob_base_fee: U256::ZERO,
                        nonce: 0,
                        slow: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        market: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        fast: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        current: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                    });
                };
                let blockhash_str = self.solana_get_latest_blockhash().await?;
                let blockhash: [u8; 32] = bs58::decode(&blockhash_str)
                    .into_vec()
                    .map_err(|e| NetworkErrors::RPCError(e.to_string()))?
                    .try_into()
                    .map_err(|_| NetworkErrors::RPCError("blockhash must be 32 bytes".into()))?;
                build_sol_transfer_message(pk, pk, 0, &blockhash)
                    .map_err(NetworkErrors::RPCError)?
            } else {
                sol_tx.message.clone()
            };
            U256::from(self.solana_get_fee_for_message(&message).await?)
        } else {
            U256::from(SOLANA_BASE_FEE_LAMPORTS)
        };

        Ok(RequiredTxParams {
            gas_price: fee,
            max_priority_fee: U256::ZERO,
            fee_history: GasFeeHistory::default(),
            tx_estimate_gas: U256::from(1u64),
            blob_base_fee: U256::ZERO,
            nonce: 0,
            slow: fee,
            market: fee,
            fast: fee,
            current: fee,
        })
    }

    async fn solana_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        let mut payloads: Vec<Value> = Vec::with_capacity(txns.len());
        let mut valid_indices: Vec<usize> = Vec::with_capacity(txns.len());

        for (i, receipt) in txns.iter().enumerate() {
            let TransactionReceipt::Solana((ref solana_receipt, ref _meta)) = receipt else {
                continue;
            };

            let wire = solana_receipt.encode();
            let encoded = base64::engine::general_purpose::STANDARD.encode(&wire);

            payloads.push(build_send_transaction_req(&encoded));
            valid_indices.push(i);
        }

        if payloads.is_empty() {
            return Ok(txns);
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<String>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        for (offset, tx_idx) in valid_indices.iter().enumerate() {
            let TransactionReceipt::Solana((_, ref mut metadata)) = txns[*tx_idx] else {
                continue;
            };
            let res = &responses[offset];
            let signature = res
                .result
                .clone()
                .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;
            metadata.hash = Some(signature);
        }

        Ok(txns)
    }

    async fn solana_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut payloads: Vec<Value> = Vec::with_capacity(txns.len());
        let mut valid_indices: Vec<usize> = Vec::with_capacity(txns.len());

        for (i, tx) in txns.iter_mut().enumerate() {
            if tx.status != TransactionStatus::Pending {
                continue;
            }

            let pending_secs = now.saturating_sub(tx.timestamp / 1000);
            if pending_secs > SOLANA_TX_PENDING_TIMEOUT_SECS {
                tx.status = TransactionStatus::Failed;
                continue;
            }

            let signature = match tx.get_solana().and_then(|v| {
                v.get("transactionHash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            }) {
                Some(sig) => sig,
                None => continue,
            };

            payloads.push(build_get_transaction_req(&signature));
            valid_indices.push(i);
        }

        if payloads.is_empty() {
            return Ok(());
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<SolanaGetTransactionResult>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        for (offset, tx_idx) in valid_indices.iter().enumerate() {
            let tx = &mut txns[*tx_idx];
            let res = &responses[offset];

            if let Some(result) = &res.result {
                let success = result
                    .meta
                    .as_ref()
                    .map(|m| m.err.is_none())
                    .unwrap_or(false);

                tx.status = if success {
                    TransactionStatus::Success
                } else {
                    TransactionStatus::Failed
                };

                if let Some(mut solana_data) = tx.get_solana() {
                    if let Some(fee) = result.meta.as_ref().and_then(|m| m.fee) {
                        solana_data["fee"] = json!(fee.to_string());
                    }
                    if let Some(slot) = result.slot {
                        solana_data["slot"] = json!(slot.to_string());
                    }
                    tx.set_solana(solana_data);
                }
            }
        }

        Ok(())
    }

    async fn solana_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        for token in tokens.iter_mut() {
            let mut payloads: Vec<Value> = Vec::new();
            let mut acc_indices: Vec<usize> = Vec::new();

            for account in accounts.iter() {
                let Address::Ed25519Solana(pubkey) = account else {
                    continue;
                };
                let address_b58 = pubkey.to_string();

                if token.native {
                    payloads.push(build_get_balance_req(&address_b58));
                    acc_indices.push(account.to_hash());
                } else if let Address::Ed25519Solana(mint) = &token.addr {
                    payloads.push(build_get_token_accounts_req(
                        &address_b58,
                        &mint.to_string(),
                    ));
                    acc_indices.push(account.to_hash());
                }
            }

            if payloads.is_empty() {
                continue;
            }

            // One batch per token — all payloads use the same RPC method, which
            // avoids the "too many requests for a specific RPC call" rate limit
            // that Solana nodes enforce per method within a batch.
            let responses: Vec<ResultRes<Value>> = provider
                .req(json!(payloads))
                .await
                .map_err(NetworkErrors::Request)?;

            for (i, acc_idx) in acc_indices.iter().enumerate() {
                if responses[i].result.is_none() {
                    continue; // RPC error — preserve stored balance
                }
                let balance = if token.native {
                    parse_native_balance(&responses[i])
                } else {
                    parse_spl_balance(&responses[i])
                };
                token.balances.insert(*acc_idx, balance);
            }
        }

        Ok(())
    }

    async fn solana_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        let Address::Ed25519Solana(mint) = contract else {
            return Err(NetworkErrors::RPCError(
                "Expected Ed25519Solana mint address".to_string(),
            ));
        };
        let mint_b58 = mint.to_string();
        let metadata_pda = metaplex_metadata_pda(&mint);

        let mut valid_accounts: Vec<usize> = Vec::with_capacity(accounts.len());
        for (i, account) in accounts.iter().enumerate() {
            if let Address::Ed25519Solana(_) = account {
                valid_accounts.push(i);
            }
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        let mint_res: ResultRes<SolanaValueResponse<Option<AccountInfoValue>>> = provider
            .req(build_get_account_info_req(&mint_b58))
            .await
            .map_err(NetworkErrors::Request)?;

        let raw_mint = mint_res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&mint_res.error)))?;

        let mint_account = raw_mint.value.ok_or_else(|| {
            NetworkErrors::RPCError(format!("Mint account not found: {mint_b58}"))
        })?;
        let decimals = mint_account.data.parsed.info.decimals;
        let mint_extensions = mint_account.data.parsed.info.extensions;

        let meta_res: ResultRes<SolanaValueResponse<Option<RawAccountValue>>> = provider
            .req(build_get_account_info_base64_req(&metadata_pda))
            .await
            .map_err(NetworkErrors::Request)?;

        let (name, symbol) = meta_res
            .result
            .and_then(|r| r.value)
            .and_then(|v| {
                let b64 = v.data.first()?;
                base64::engine::general_purpose::STANDARD.decode(b64).ok()
            })
            .and_then(|bytes| MetaplexMetadata::from_bytes(&bytes))
            .map(|m| (m.name, m.symbol))
            .filter(|(n, s)| !n.is_empty() || !s.is_empty())
            .or_else(|| extract_token2022_metadata(&mint_extensions))
            .unwrap_or_default();

        let mut balances = HashMap::new();
        for &acc_idx in &valid_accounts {
            let account = accounts[acc_idx];
            if let Address::Ed25519Solana(pubkey) = account {
                let bal_res: ResultRes<Value> = provider
                    .req(build_get_token_accounts_req(&pubkey.to_string(), &mint_b58))
                    .await
                    .map_err(NetworkErrors::Request)?;
                balances.insert(account.to_hash(), parse_spl_balance(&bal_res));
            }
        }

        Ok(FToken {
            name,
            symbol,
            decimals,
            addr: Address::Ed25519Solana(mint),
            logo: Some(format!("{SOLANA_TOKEN_LOGO_URL}/{mint_b58}/logo.png")),
            balances,
            default: false,
            native: false,
            chain_hash: self.config.hash(),
            rate: 0f64,
        })
    }
}

fn build_get_balance_req(address_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([address_b58, {"commitment": "finalized"}]),
        SolanaMethod::GetBalance,
    )
}

fn build_get_token_accounts_req(address_b58: &str, mint_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([address_b58, {"mint": mint_b58}, {"encoding": "jsonParsed", "commitment": "finalized"}]),
        SolanaMethod::GetTokenAccountsByOwner,
    )
}

fn build_get_account_info_req(mint_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([mint_b58, {"encoding": "jsonParsed"}]),
        SolanaMethod::GetAccountInfo,
    )
}

fn build_get_account_info_base64_req(address_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([address_b58, {"encoding": "base64"}]),
        SolanaMethod::GetAccountInfo,
    )
}

fn parse_lookup_table_account(key: Pubkey, data: &[u8]) -> Result<AddressLookupTableAccount> {
    let table = AddressLookupTable::deserialize(data)
        .map_err(|error| NetworkErrors::RPCError(error.to_string()))?;
    let mut addresses = Vec::with_capacity(table.addresses.len());
    addresses.extend(table.addresses.iter().copied());
    Ok(AddressLookupTableAccount { key, addresses })
}

impl NetworkProvider {
    async fn solana_get_lookup_table_accounts(
        &self,
        addresses: &[Pubkey],
    ) -> Result<Vec<AddressLookupTableAccount>> {
        let encoded_addresses: Vec<String> = addresses.iter().map(Pubkey::to_string).collect();
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([encoded_addresses, {"encoding": "base64"}]),
            SolanaMethod::GetMultipleAccounts,
        );
        let res: ResultRes<SolanaValueResponse<Vec<Option<RawAccountValue>>>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        addresses
            .iter()
            .copied()
            .zip(value.value)
            .map(|(key, account)| {
                let account = account.ok_or_else(|| {
                    NetworkErrors::RPCError(format!("lookup table account not found: {key}"))
                })?;
                let data = account.data.first().ok_or_else(|| {
                    NetworkErrors::RPCError(format!("lookup table account missing data: {key}"))
                })?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|error| NetworkErrors::RPCError(error.to_string()))?;
                parse_lookup_table_account(key, &bytes)
            })
            .collect()
    }
}

fn metaplex_metadata_pda(mint: &Pubkey) -> String {
    let program_id: Pubkey = METAPLEX_PROGRAM_ID.parse().expect("valid metaplex id");
    let (pda, _) = Pubkey::find_program_address(
        &[METAPLEX_METADATA_SEED, program_id.as_ref(), mint.as_ref()],
        &program_id,
    );
    pda.to_string()
}

fn build_get_transaction_req(sig: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}]),
        SolanaMethod::GetTransaction,
    )
}

fn build_send_transaction_req(encoded: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([encoded, {"encoding": "base64"}]),
        SolanaMethod::SendTransaction,
    )
}

fn parse_native_balance(raw: &ResultRes<Value>) -> U256 {
    raw.result
        .as_ref()
        .and_then(|v| serde_json::from_value::<SolanaValueResponse<u64>>(v.clone()).ok())
        .map(|r| U256::from(r.value))
        .unwrap_or(U256::ZERO)
}

fn parse_spl_balance(raw: &ResultRes<Value>) -> U256 {
    raw.result
        .as_ref()
        .and_then(|v| {
            serde_json::from_value::<SolanaValueResponse<Vec<TokenAccountEntry>>>(v.clone()).ok()
        })
        .and_then(|r| r.value.into_iter().next())
        .and_then(|e| {
            e.account
                .data
                .parsed
                .info
                .token_amount
                .amount
                .parse::<u64>()
                .ok()
        })
        .map(U256::from)
        .unwrap_or(U256::ZERO)
}

fn solana_err_msg(err: &Option<ErrorRes>) -> String {
    err.as_ref()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "Solana RPC: empty result".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::solana_tx::SolanaTransaction;
    use proto::tx::TransactionMetadata;
    use test_data::{gen_sol_devnet_conf, gen_sol_mainnet_conf, gen_sol_spl_token, gen_sol_token};

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    const DEVNET_USDC_RICH_ADDRESS: &str = "DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY";
    const MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const MAINNET_USDC_RICH_ADDRESS: &str = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
    const DEVNET_ZERO_ADDRESS: &str = "4fYNw3dojWmQ4dXtSGE9epjRGy9GHeo5UCCbg6NbyNjF";
    const DEVNET_CONFIRMED_TX_SIG: &str =
        "x7SUrZF6nV97XF1hg2NPZpLimi6StUbpH2nVdGC4jR2ojnnzYQ18y4CpLnCR6JkcH4gCQgW3sobJC2wVcnQE2xR";
    const DEVNET_FAILED_TX_SIG: &str =
        "2V2erUdPadyTiFRFS98g6kkXHDVFgWX1ZeDMH67bpsPekm9BaCCkLs6rN15Y6oDeHWETFb5sagfR7syifbWLPMcG";

    #[tokio::test]
    async fn test_solana_get_block_number() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let slot = provider.solana_get_current_block_number().await.unwrap();
        assert!(slot > 0);
    }

    #[tokio::test]
    async fn test_solana_estimate_block_time() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let t = provider.solana_estimate_block_time().await.unwrap();
        assert_eq!(t, SOLANA_BLOCK_TIME_SECS);
    }

    #[tokio::test]
    async fn test_solana_get_latest_blockhash() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let hash = provider.solana_get_latest_blockhash().await.unwrap();
        assert!(hash.len() >= 32, "blockhash too short: {}", hash);
        let decoded = bs58::decode(&hash).into_vec();
        assert!(decoded.is_ok(), "blockhash is not valid base58");
        assert_eq!(decoded.unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_solana_estimate_params_batch() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let tx =
            TransactionRequest::Solana((SolanaTransaction { message: vec![] }, Default::default()));
        let sender = Address::Ed25519Solana([1u8; 32].into());
        let params = provider
            .solana_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        assert_eq!(params.gas_price, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.slow, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.market, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.fast, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.nonce, 0);
        assert_eq!(params.blob_base_fee, U256::ZERO);
    }

    #[tokio::test]
    async fn test_solana_update_balances_zero_address() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let zero_account = Address::Ed25519Solana([0u8; 32].into());

        provider
            .solana_update_balances(vec![&mut token], &[&zero_account])
            .await
            .unwrap();

        assert!(token.balances.contains_key(&zero_account.to_hash()));
    }

    #[tokio::test]
    async fn test_solana_update_balances_skips_non_solana() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let eth_account = Address::Secp256k1Keccak256([0u8; 20]);

        provider
            .solana_update_balances(vec![&mut token], &[&eth_account])
            .await
            .unwrap();

        assert!(token.balances.is_empty());
    }

    #[tokio::test]
    async fn test_solana_update_transactions_receipt_unknown_sig() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some("1111111111111111111111111111111111111111111111111111111111111111".to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": "1111111111111111111111111111111111111111111111111111111111111111"
            })).ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        assert_eq!(list[0].status, TransactionStatus::Pending);
    }

    #[tokio::test]
    async fn test_solana_get_block_number_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let slot = provider.solana_get_current_block_number().await.unwrap();
        dbg!(&slot);
        assert!(
            slot > 453_000_000,
            "Slot should be > 453M on devnet, got: {}",
            slot
        );
    }

    #[tokio::test]
    async fn test_solana_get_latest_blockhash_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let hash = provider.solana_get_latest_blockhash().await.unwrap();
        dbg!(&hash);
        assert!(!hash.is_empty(), "Blockhash should not be empty");
        let decoded = bs58::decode(&hash).into_vec().unwrap();
        assert_eq!(decoded.len(), 32, "Blockhash must decode to 32 bytes");
        println!("Blockhash decoded {} bytes successfully", decoded.len());
    }

    #[tokio::test]
    async fn test_solana_update_balances_rich_address() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let rich_account = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();
        println!("Querying balance for address: {}", DEVNET_RICH_ADDRESS);

        provider
            .solana_update_balances(vec![&mut token], &[&rich_account])
            .await
            .unwrap();

        let balance = token.balances.get(&rich_account.to_hash()).unwrap();
        dbg!(balance);
        assert!(
            *balance > U256::from(0),
            "Rich address should have SOL balance"
        );
        println!(
            "Balance: {} lamports ({} SOL)",
            balance,
            balance / U256::from(1_000_000_000u64)
        );
    }

    #[tokio::test]
    async fn test_solana_update_balances_zero_address_real() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        println!(
            "Querying balance for zero-balance address: {}",
            DEVNET_ZERO_ADDRESS
        );

        provider
            .solana_update_balances(vec![&mut token], &[&zero_account])
            .await
            .unwrap();

        let balance = token.balances.get(&zero_account.to_hash()).unwrap();
        dbg!(balance);
        assert_eq!(
            *balance,
            U256::from(0),
            "Empty address should have zero balance"
        );
        println!("Balance confirmed: 0 lamports");
    }

    #[tokio::test]
    async fn test_solana_update_balances_multiple_accounts() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let rich_account = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        let accounts: Vec<&Address> = vec![&rich_account, &zero_account];

        println!("Querying balances for {} accounts", accounts.len());
        provider
            .solana_update_balances(vec![&mut token], &accounts)
            .await
            .unwrap();

        let rich_balance = token.balances.get(&rich_account.to_hash()).unwrap();
        let zero_balance = token.balances.get(&zero_account.to_hash()).unwrap();
        dbg!(rich_balance, zero_balance);

        assert!(*rich_balance > U256::from(0));
        assert_eq!(*zero_balance, U256::from(0));
        println!("Multi-account balance check passed");
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_confirmed() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_CONFIRMED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_CONFIRMED_TX_SIG
            }))
            .ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Querying confirmed tx: {}", DEVNET_CONFIRMED_TX_SIG);
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        let solana_data = list[0].get_solana().unwrap();
        dbg!(&solana_data);
        dbg!(&list[0].status);
        assert_eq!(
            list[0].status,
            TransactionStatus::Success,
            "Confirmed tx should be Success"
        );

        let fee = solana_data.get("fee").and_then(|v| v.as_str());
        assert!(fee.is_some(), "Fee should be set in solana data");
        println!("Confirmed tx fee: {:?}", fee);

        let slot = solana_data.get("slot").and_then(|v| v.as_str());
        assert!(slot.is_some(), "Slot should be set in solana data");
        println!("Confirmed tx slot: {:?}", slot);
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_failed() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_FAILED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_FAILED_TX_SIG
            }))
            .ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Querying failed tx: {}", DEVNET_FAILED_TX_SIG);
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        dbg!(&list[0].status);
        assert_eq!(
            list[0].status,
            TransactionStatus::Failed,
            "Failed tx should be Failed status"
        );

        let solana_data = list[0].get_solana().unwrap();
        dbg!(&solana_data);
        println!("Failed tx data: {:?}", solana_data);
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_skips_non_pending() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Success,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_CONFIRMED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_CONFIRMED_TX_SIG
            }))
            .ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Testing that non-pending tx is skipped");
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        assert_eq!(
            list[0].status,
            TransactionStatus::Success,
            "Should remain Success"
        );
        println!("Non-pending tx correctly skipped");
    }

    #[tokio::test]
    async fn test_solana_estimate_params_batch_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let tx =
            TransactionRequest::Solana((SolanaTransaction { message: vec![] }, Default::default()));
        let sender = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();

        let params = provider
            .solana_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        dbg!(&params);
        assert_eq!(params.gas_price, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.slow, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.market, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.fast, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.tx_estimate_gas, U256::from(1u64));
        assert_eq!(params.nonce, 0);
        println!(
            "Fee params validated: gas_price={} lamports",
            SOLANA_BASE_FEE_LAMPORTS
        );
    }

    fn usdc_mint_bytes() -> [u8; 32] {
        bs58::decode(DEVNET_USDC_MINT)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn mainnet_usdc_mint_bytes() -> [u8; 32] {
        bs58::decode(MAINNET_USDC_MINT)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[tokio::test]
    async fn test_solana_update_balances_spl_rich_address() {
        let conf = gen_sol_devnet_conf();
        let provider = NetworkProvider::new(conf.clone());
        let mut token = gen_sol_spl_token(usdc_mint_bytes(), conf.hash());
        let rich_account = Address::from_solana_address(DEVNET_USDC_RICH_ADDRESS).unwrap();
        println!(
            "Querying SPL USDC balance for: {}",
            DEVNET_USDC_RICH_ADDRESS
        );

        provider
            .solana_update_balances(vec![&mut token], &[&rich_account])
            .await
            .unwrap();

        let balance = token.balances.get(&rich_account.to_hash()).unwrap();
        dbg!(&token);
        assert!(
            *balance > U256::ZERO,
            "Rich address should have USDC balance"
        );
        println!("SPL USDC balance: {} (raw units)", balance);
    }

    #[test]
    fn test_metaplex_pda_mainnet_usdc() {
        let mainnet_usdc: Pubkey = MAINNET_USDC_MINT.parse().unwrap();
        let program_id: Pubkey = METAPLEX_PROGRAM_ID.parse().unwrap();
        let (pda, _) = Pubkey::find_program_address(
            &[
                METAPLEX_METADATA_SEED,
                program_id.as_ref(),
                mainnet_usdc.as_ref(),
            ],
            &program_id,
        );
        assert_eq!(
            pda.to_string(),
            "5x38Kp4hvdomTCnCrAny4UtMUt5rQBdB6px2K1Ui45Wq",
            "PDA mismatch for mainnet USDC"
        );
    }

    #[tokio::test]
    async fn test_solana_ftoken_meta_usdc() {
        let provider = NetworkProvider::new(gen_sol_mainnet_conf());
        let mint = Address::Ed25519Solana(mainnet_usdc_mint_bytes().into());
        let rich_account = Address::from_solana_address(MAINNET_USDC_RICH_ADDRESS).unwrap();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();

        let ftoken = provider
            .solana_ftoken_meta(mint, &[&rich_account, &zero_account])
            .await
            .unwrap();

        dbg!(&ftoken.decimals);
        dbg!(&ftoken.name);
        dbg!(&ftoken.symbol);
        dbg!(ftoken.balances.get(&rich_account.to_hash()));
        dbg!(ftoken.balances.get(&zero_account.to_hash()));
        assert_eq!(ftoken.decimals, 6);
        assert_eq!(ftoken.name, "USD Coin");
        assert_eq!(ftoken.symbol, "USDC");
        assert!(!ftoken.native);
        assert_eq!(
            ftoken.logo.as_deref(),
            Some(
                "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png"
            )
        );
        assert!(
            *ftoken.balances.get(&rich_account.to_hash()).unwrap() > U256::ZERO,
            "Rich address should have USDC"
        );
        assert_eq!(
            *ftoken.balances.get(&zero_account.to_hash()).unwrap(),
            U256::ZERO,
            "Zero address should have no USDC"
        );
    }

    #[tokio::test]
    async fn test_solana_ftoken_meta_pump() {
        let provider = NetworkProvider::new(gen_sol_mainnet_conf());
        let mint =
            Address::from_solana_address("AsCoZ4io1XeCdKyFo2NB27qZJaupQYpPnEEjT1btpump").unwrap();

        let ftoken = provider.solana_ftoken_meta(mint, &[]).await.unwrap();

        dbg!(&ftoken.name);
        dbg!(&ftoken.symbol);
        dbg!(&ftoken.decimals);
        dbg!(&ftoken.logo);
        assert!(
            !ftoken.name.is_empty(),
            "pump.fun token name must not be empty"
        );
        assert!(ftoken.logo.is_some(), "pump.fun token should have logo URL");
        assert!(
            !ftoken.symbol.is_empty(),
            "pump.fun token symbol must not be empty"
        );
    }
}
