use async_trait::async_trait;
use crypto::slip44::TRON;
use errors::rpc::RpcError;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{fmt::Debug, time::Duration};

use crate::common::{JsonRPC, NetworkConfigTrait, Result, RpcMethod};

pub struct RpcProvider<'a, N>
where
    N: NetworkConfigTrait,
{
    pub network: &'a N,
    client: reqwest::Client,
}

impl<'a, N> RpcProvider<'a, N>
where
    N: NetworkConfigTrait,
{
    pub fn new(network: &'a N) -> Self {
        Self {
            network,
            client: reqwest::Client::new(),
        }
    }

    pub fn build_payload<M: RpcMethod>(params: Value, method: M) -> Value {
        serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method.as_str(),
            "params": params
        })
    }

    async fn req_evm<SR>(&self, payloads: Value) -> Result<SR>
    where
        SR: DeserializeOwned + Debug,
    {
        const TIME_OUT_SEC: u64 = 5;
        let mut last_error = None;
        let mut errors = String::with_capacity(200);

        let is_tron = self.network.get_slip44() == TRON;
        let is_batch = payloads.is_array();
        let prepared = if is_batch {
            if let Value::Array(mut arr) = payloads {
                for (i, item) in arr.iter_mut().enumerate() {
                    item["id"] = serde_json::json!((i as u64) + 1);
                }
                Value::Array(arr)
            } else {
                unreachable!()
            }
        } else {
            payloads
        };

        for url in self.network.nodes() {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                continue;
            }

            let rpc_url = if is_tron {
                let base = url.trim_end_matches('/');
                format!("{}/jsonrpc", base)
            } else {
                url.clone()
            };

            let res = self
                .client
                .post(rpc_url)
                .timeout(Duration::from_secs(TIME_OUT_SEC))
                .json(&prepared)
                .send()
                .await;

            match res {
                Ok(response) => match response.text().await {
                    Ok(text) => {
                        let result = if is_batch {
                            let parsed = serde_json::from_str::<Vec<Value>>(&text);
                            match parsed {
                                Ok(mut values) => {
                                    values.sort_by_key(|v| {
                                        v.get("id").and_then(|i| i.as_u64()).unwrap_or(0)
                                    });
                                    serde_json::from_value::<SR>(Value::Array(values))
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            serde_json::from_str::<SR>(&text)
                        };
                        match result {
                            Ok(json) => return Ok(json),
                            Err(e) => {
                                errors.push_str(&format!(
                                    "Failed to parse JSON: {}. Response: {}",
                                    e, text
                                ));
                                last_error = Some(RpcError::InvalidJson(errors.to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        errors.push_str(&format!("Failed to get response text: {}", e));
                        last_error = Some(RpcError::BadRequest(errors.to_string()));
                    }
                },
                Err(e) => {
                    errors.push_str(&format!("Request failed: {}", e));
                    last_error = Some(RpcError::BadRequest(errors.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or(RpcError::NetworkDown))
    }

    async fn req_btc<SR>(&self, _payloads: Value) -> Result<SR>
    where
        SR: DeserializeOwned + Debug,
    {
        Err(RpcError::NetworkDown)
    }
}

#[async_trait]
impl<'a, N> JsonRPC for RpcProvider<'a, N>
where
    N: NetworkConfigTrait + Send + Sync,
{
    fn get_nodes(&self) -> &[String] {
        self.network.nodes()
    }

    async fn req<SR>(&self, payloads: Value) -> Result<SR>
    where
        SR: DeserializeOwned + Debug,
    {
        const BTC_SLIP44: u32 = 0;

        if self.network.get_slip44() == BTC_SLIP44 {
            self.req_btc(payloads).await
        } else {
            self.req_evm(payloads).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        methods::{EvmMethods, ZilMethods},
        network_config::{ChainConfig, Explorer},
        zil_interfaces::{GetBalanceRes, ResultRes},
    };
    use serde_json::json;

    const ZERO_ADDR: &str = "0000000000000000000000000000000000000000";

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![155],
            slip_44: 313,
            ens: None,
            explorers: vec![Explorer {
                name: "ViewBlock".to_string(),
                url: "https://viewblock.io/zilliqa".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn create_eth_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            chain_ids: [11155111, 0],
            testnet: None,
            name: "Ethereum Mainnet".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec![
                "https://rpc.sepolia.org".to_string(),
                "https://rpc2.sepolia.org".to_string(),
                "https://rpc.sepolia.online".to_string(),
                "https://www.sepoliarpc.space".to_string(),
                "https://rpc.bordel.wtf/sepolia".to_string(),
                "https://rpc-sepolia.rockx.com".to_string(),
            ],
            features: vec![155, 1559],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_balance_scilla() {
        let net_conf = create_zilliqa_config();
        let zil: RpcProvider<ChainConfig> = RpcProvider::new(&net_conf);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!([ZERO_ADDR]),
            ZilMethods::GetBalance,
        )];

        let res: Vec<ResultRes<GetBalanceRes>> = zil.req(payloads.into()).await.unwrap();

        assert_eq!(res.len(), 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }

    #[test]
    fn test_build_payload() {
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!(["param1", "param2"]),
            EvmMethods::GetBalance,
        );

        assert_eq!(payload["jsonrpc"], "2.0");
        assert_eq!(payload["id"], 1);
        assert_eq!(payload["method"], EvmMethods::GetBalance.as_str());
        assert!(payload["params"].is_array());
        assert_eq!(payload["params"][0], "param1");
        assert_eq!(payload["params"][1], "param2");
    }

    #[tokio::test]
    async fn test_network_much_req() {
        let config = create_eth_config();
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&config);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!(["0x246C5881E3F109B2aF170F5C773EF969d3da581B", "latest"]),
            EvmMethods::GetBalance,
        )];

        let result: Result<Vec<ResultRes<String>>> = provider.req(payloads.into()).await;

        dbg!(&result);
    }

    #[tokio::test]
    async fn test_btc_get_balance() {
        use bitcoin::Address;
        use electrum_client::{Client as ElectrumClient, ConfigBuilder, ElectrumApi};

        let addresses = vec![
            "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z",
            "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z",
            "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z",
        ];

        let scripts: Vec<_> = addresses
            .iter()
            .map(|addr| {
                let address = addr.parse::<Address<_>>().unwrap().assume_checked();
                address.script_pubkey()
            })
            .collect();

        println!("\nQuerying {} addresses in batch:", addresses.len());
        for (i, addr) in addresses.iter().enumerate() {
            println!("  {}: {}", i, addr);
        }

        let url = "ssl://btc-testnet.zilpay.io:60402";
        let config = ConfigBuilder::new().timeout(Some(5)).build();

        match ElectrumClient::from_config(url, config) {
            Ok(client) => {
                let script_refs: Vec<_> = scripts.iter().map(|s| s.as_ref()).collect();
                let balances = client.batch_script_get_balance(&script_refs);
                let history = client.batch_script_get_history(&script_refs);

                dbg!(&history);

                assert!(balances.is_ok());

                let bals = balances.unwrap();
                println!("\nBatch balance results:");
                for (i, bal) in bals.iter().enumerate() {
                    println!(
                        "  Address {}: Confirmed: {} sats, Unconfirmed: {} sats",
                        i, bal.confirmed, bal.unconfirmed
                    );
                }
                assert_eq!(bals.len(), addresses.len());
            }
            Err(e) => {
                panic!("Failed to connect: {}", e);
            }
        }
    }
}
