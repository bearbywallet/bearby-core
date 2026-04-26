use std::collections::HashMap;

use alloy::primitives::U256;
use async_trait::async_trait;
use config::contracts::{SCILLA_GZIL_CONTRACT, SCILLA_STAKE_PROXY, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    tx::{TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use rpc::{
    common::JsonRPC, methods::ZilMethods, network_config::ChainConfig, provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::stake::{FinalOutput, PendingWithdrawal};
use crate::provider::NetworkProvider;

#[derive(Deserialize, Debug)]
struct WithdrawalUnbonded {
    pub arguments: (String, String),
}

#[derive(Debug, Default)]
struct RewardCalculationData {
    last_reward_cycle: u64,
    last_withdraw_cycle_map: Value,
    stake_ssn_per_cycle_maps: HashMap<String, Value>,
    direct_deposit_maps: HashMap<String, Value>,
    buff_deposit_maps: HashMap<String, Value>,
}

#[async_trait]
pub trait ZilliqaScillaStakeing {
    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;

    async fn batch_query(
        &self,
        queries: &[(&str, &str, Vec<String>)],
    ) -> Result<Vec<ResultRes<Value>>, NetworkErrors>;

    async fn fetch_scilla_stake(
        &self,
        wallet_address: &Address,
    ) -> Result<Vec<FinalOutput>, NetworkErrors>;
}

#[async_trait]
impl ZilliqaScillaStakeing for NetworkProvider {
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawTokensAmt",
          "params": [
            {
              "vname": "amount",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(ST_ZIL_CONTRACT)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            broadcast: true,
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "CompleteWithdrawal",
            "params": []
        });
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 100000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            broadcast: true,
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawStakeAmt",
          "params": [
            {
              "vname": "ssnaddr",
              "type": "ByStr20",
              "value": stake.address
            },
            {
              "vname": "amt",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            broadcast: true,
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "WithdrawStakeRewards",
            "params": [
                {
                    "vname": "ssnaddr",
                    "type": "ByStr20",
                    "value": stake.address
                }
            ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 100000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            broadcast: true,
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    async fn fetch_scilla_stake(
        &self,
        user_address: &Address,
    ) -> Result<Vec<FinalOutput>, NetworkErrors> {
        let wallet_address = user_address.get_zil_check_sum_addr()?.to_lowercase();
        let mut staked_nodes: Vec<FinalOutput> = Vec::new();
        let initial_queries = [
            (
                SCILLA_GZIL_CONTRACT,
                "deposit_amt_deleg",
                vec![wallet_address.to_string()],
            ),
            (SCILLA_GZIL_CONTRACT, "ssnlist", vec![]),
            (SCILLA_GZIL_CONTRACT, "lastrewardcycle", vec![]),
            (
                SCILLA_GZIL_CONTRACT,
                "last_withdraw_cycle_deleg",
                vec![wallet_address.to_string()],
            ),
            (
                ST_ZIL_CONTRACT,
                "balances",
                vec![wallet_address.to_string()],
            ),
            (
                SCILLA_GZIL_CONTRACT,
                "withdrawal_pending",
                vec![wallet_address.to_string()],
            ),
            (
                ST_ZIL_CONTRACT,
                "withdrawal_unbonded",
                vec![wallet_address.to_string()],
            ),
        ];
        let initial_results = self.batch_query(&initial_queries).await?;
        let deposits_result = initial_results
            .first()
            .and_then(|r| r.result.as_ref())
            .unwrap_or(&Value::Null);
        let ssn_list_result = initial_results
            .get(1)
            .and_then(|r| r.result.as_ref())
            .ok_or_else(|| NetworkErrors::ParseHttpError("ssnlist".into()))?;
        let last_reward_cycle_result = initial_results
            .get(2)
            .and_then(|r| r.result.as_ref())
            .ok_or_else(|| NetworkErrors::ParseHttpError("lastrewardcycle".into()))?;
        let last_withdraw_result = initial_results
            .get(3)
            .and_then(|r| r.result.as_ref())
            .unwrap_or(&Value::Null);
        let st_zil_balance_result = initial_results.get(4).and_then(|r| r.result.as_ref());
        let withdrawal_pending_result = initial_results.get(5).and_then(|r| r.result.as_ref());
        let unbonded_withdrawal_result = initial_results.get(6).and_then(|r| r.result.as_ref());
        let unbonded_withdrawal: Option<WithdrawalUnbonded> = unbonded_withdrawal_result
            .and_then(|r| r.get("withdrawal_unbonded"))
            .and_then(|wu| wu.get(&wallet_address))
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        if let Some(unbonded) = unbonded_withdrawal {
            let zil = unbonded.arguments.1.parse::<U256>().unwrap_or_default();
            let st_zil = unbonded.arguments.0.parse::<U256>().unwrap_or_default();

            if zil > U256::ZERO {
                staked_nodes.push(FinalOutput {
                    name: "Avely (legacy) Claim".to_string(),
                    address: ST_ZIL_CONTRACT.to_string(),
                    tag: "scilla".to_string(),
                    rewards: st_zil,
                    pending_withdrawals: vec![PendingWithdrawal {
                        amount: zil,
                        withdrawal_block: 0,
                        claimable: true,
                    }],
                    ..Default::default()
                });
            }
        }

        if let Some(result) = st_zil_balance_result {
            if let Some(balances_map) = result.get("balances") {
                if let Some(balance_str) =
                    balances_map.get(&wallet_address).and_then(|v| v.as_str())
                {
                    let balance = balance_str.parse().unwrap_or(U256::ZERO);

                    if balance > U256::ZERO {
                        staked_nodes.push(FinalOutput {
                            name: "Avely (legacy)".to_string(),
                            address: ST_ZIL_CONTRACT.to_string(),
                            token: None,
                            deleg_amt: balance,
                            rewards: U256::ZERO,
                            apr: None,
                            commission: None,
                            tag: "scilla".to_string(),
                            current_block: None,
                            pending_withdrawals: vec![],
                            ..Default::default()
                        });
                    }
                }
            }
        }

        let user_deposits: HashMap<String, String> = deposits_result
            .get("deposit_amt_deleg")
            .and_then(|m| m.get(&wallet_address))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let mut total_staked = U256::ZERO;
        let mut total_rewards = U256::ZERO;

        if !user_deposits.is_empty() {
            let ssn_list = ssn_list_result
                .get("ssnlist")
                .and_then(|v| v.as_object())
                .ok_or_else(|| NetworkErrors::ParseHttpError("ssnlist map".into()))?;

            let staked_ssn_addresses: Vec<_> = user_deposits.keys().cloned().collect();
            let mut reward_queries: Vec<(&str, &str, Vec<String>)> = Vec::new();

            for ssn_addr in &staked_ssn_addresses {
                reward_queries.push((
                    SCILLA_GZIL_CONTRACT,
                    "stake_ssn_per_cycle",
                    vec![ssn_addr.clone()],
                ));
                reward_queries.push((
                    SCILLA_GZIL_CONTRACT,
                    "direct_deposit_deleg",
                    vec![wallet_address.to_string(), ssn_addr.clone()],
                ));
                reward_queries.push((
                    SCILLA_GZIL_CONTRACT,
                    "buff_deposit_deleg",
                    vec![wallet_address.to_string(), ssn_addr.clone()],
                ));
            }

            let reward_query_results = self.batch_query(&reward_queries).await?;

            let mut reward_data = RewardCalculationData {
                last_reward_cycle: last_reward_cycle_result["lastrewardcycle"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
                last_withdraw_cycle_map: last_withdraw_result.to_owned(),
                ..Default::default()
            };

            let mut query_iter = reward_query_results.into_iter();
            for ssn_addr in &staked_ssn_addresses {
                reward_data.stake_ssn_per_cycle_maps.insert(
                    ssn_addr.clone(),
                    query_iter.next().unwrap().result.unwrap_or_default(),
                );
                reward_data.direct_deposit_maps.insert(
                    ssn_addr.clone(),
                    query_iter.next().unwrap().result.unwrap_or_default(),
                );
                reward_data.buff_deposit_maps.insert(
                    ssn_addr.clone(),
                    query_iter.next().unwrap().result.unwrap_or_default(),
                );
            }

            let rewards_by_ssn = calculate_rewards(&wallet_address, &user_deposits, &reward_data);

            for (ssn_address, stake_amount_str) in &user_deposits {
                let ssn_info = match ssn_list.get(ssn_address) {
                    Some(info) => info,
                    None => {
                        continue;
                    }
                };

                let ssn_args = ssn_info
                    .get("arguments")
                    .and_then(|a| a.as_array())
                    .unwrap();
                let ssn_name = ssn_args[3].as_str().unwrap_or("Неизвестно").to_string();
                let commission_rate = ssn_args[7]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(U256::ZERO);
                let stake_amount = stake_amount_str.parse().unwrap_or(U256::ZERO);
                let rewards_amount = rewards_by_ssn
                    .get(ssn_address)
                    .cloned()
                    .unwrap_or(U256::ZERO);

                total_staked += &stake_amount;
                total_rewards += &rewards_amount;

                staked_nodes.push(FinalOutput {
                    name: ssn_name,
                    address: ssn_address.to_string(),
                    token: None,
                    deleg_amt: stake_amount,
                    rewards: rewards_amount,
                    apr: None,
                    commission: Some(f64::from(commission_rate) / 10000000.0),
                    tag: "scilla".to_string(),
                    current_block: None,
                    pending_withdrawals: vec![],
                    ..Default::default()
                });
            }
        }

        if let Some(wp_res) = withdrawal_pending_result {
            if let Some(pending_map) = wp_res
                .get("withdrawal_pending")
                .and_then(|m| m.get(&wallet_address))
                .and_then(|v| v.as_object())
            {
                if !pending_map.is_empty() {
                    for (_, amount) in pending_map {
                        let amount = amount
                            .as_str()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(U256::ZERO);
                        staked_nodes.push(FinalOutput {
                            name: "Scilla Withdrawals".to_string(),
                            address: SCILLA_STAKE_PROXY.to_string(),
                            token: None,
                            deleg_amt: amount,
                            rewards: U256::ZERO,
                            apr: None,
                            commission: None,
                            tag: "scilla".to_string(),
                            current_block: None,
                            pending_withdrawals: vec![PendingWithdrawal {
                                amount,
                                withdrawal_block: 0,
                                claimable: true,
                            }],
                            ..Default::default()
                        });
                    }
                }
            }
        }

        Ok(staked_nodes)
    }

    async fn batch_query(
        &self,
        queries: &[(&str, &str, Vec<String>)],
    ) -> Result<Vec<ResultRes<Value>>, NetworkErrors> {
        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let request_body_final = queries
            .iter()
            .map(|query| {
                let params_values: Vec<Value> =
                    query.2.iter().map(|s| Value::from(s.clone())).collect();

                RpcProvider::<ChainConfig>::build_payload(
                    json!([query.0, query.1, params_values]),
                    ZilMethods::GetSmartContractSubState,
                )
            })
            .collect::<Vec<Value>>();
        let json_response = provider
            .req::<Vec<ResultRes<Value>>>(request_body_final.into())
            .await
            .map_err(NetworkErrors::Request)?;

        for res in &json_response {
            if let Some(errors) = &res.error {
                let error = errors.to_string();
                return Err(NetworkErrors::RPCError(error));
            }
        }

        Ok(json_response)
    }
}

fn calculate_rewards(
    normalized_address: &str,
    user_deposits: &HashMap<String, String>,
    reward_data: &RewardCalculationData,
) -> HashMap<String, U256> {
    let mut rewards_by_ssn = HashMap::new();
    let zero_bigint = U256::ZERO;

    for ssn_address in user_deposits.keys() {
        let mut total_ssn_reward = U256::ZERO;

        let last_withdraw_cycle_str = reward_data
            .last_withdraw_cycle_map
            .get("last_withdraw_cycle_deleg")
            .and_then(|m| m.get(normalized_address))
            .and_then(|m| m.get(ssn_address))
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        let last_withdraw_cycle: u64 = last_withdraw_cycle_str.parse().unwrap_or(0);

        if last_withdraw_cycle >= reward_data.last_reward_cycle {
            rewards_by_ssn.insert(ssn_address.clone(), U256::ZERO);
            continue;
        }

        let ssn_cycle_info_map = reward_data
            .stake_ssn_per_cycle_maps
            .get(ssn_address)
            .and_then(|v| v.get("stake_ssn_per_cycle"))
            .and_then(|m| m.get(ssn_address));

        let direct_map = reward_data
            .direct_deposit_maps
            .get(ssn_address)
            .and_then(|v| {
                v.pointer(&format!(
                    "/direct_deposit_deleg/{}/{}",
                    normalized_address, ssn_address
                ))
            });

        let buff_map = reward_data
            .buff_deposit_maps
            .get(ssn_address)
            .and_then(|v| {
                v.pointer(&format!(
                    "/buff_deposit_deleg/{}/{}",
                    normalized_address, ssn_address
                ))
            });

        let mut deleg_stake_per_cycle_map = HashMap::new();

        for cycle in 1..=reward_data.last_reward_cycle {
            let c1 = cycle.saturating_sub(1);
            let c2 = cycle.saturating_sub(2);

            let dir_amt = direct_map
                .and_then(|m| m.get(c1.to_string()))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(U256::ZERO);
            let buf_amt = buff_map
                .and_then(|m| m.get(c2.to_string()))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(U256::ZERO);
            let last_amt = *deleg_stake_per_cycle_map.get(&c1).unwrap_or(&zero_bigint);

            deleg_stake_per_cycle_map.insert(cycle, last_amt + dir_amt + buf_amt);
        }

        for cycle in (last_withdraw_cycle + 1)..=reward_data.last_reward_cycle {
            if let Some(cycle_info) = ssn_cycle_info_map.and_then(|m| m.get(cycle.to_string())) {
                let total_stake_for_cycle_str = cycle_info
                    .get("arguments")
                    .and_then(|a| a.get(0))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                let total_rewards_for_cycle_str = cycle_info
                    .get("arguments")
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");

                let total_stake_for_cycle = total_stake_for_cycle_str.parse().unwrap_or(U256::ZERO);
                let total_rewards_for_cycle =
                    total_rewards_for_cycle_str.parse().unwrap_or(U256::ZERO);

                if let Some(deleg_stake_for_cycle) = deleg_stake_per_cycle_map.get(&cycle) {
                    if !deleg_stake_for_cycle.is_zero() && !total_stake_for_cycle.is_zero() {
                        total_ssn_reward += (deleg_stake_for_cycle * total_rewards_for_cycle)
                            / total_stake_for_cycle;
                    }
                }
            }
        }
        rewards_by_ssn.insert(ssn_address.clone(), total_ssn_reward);
    }

    rewards_by_ssn
}
