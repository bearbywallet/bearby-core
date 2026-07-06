use alloy::primitives::{Address as AlloyAddress, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct PendingWithdrawal {
    pub amount: U256,
    pub withdrawal_block: u64,
    pub claimable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LPToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub address: AlloyAddress,
    pub price: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FinalOutput {
    pub name: String,
    pub address: String,
    pub token: Option<LPToken>,
    pub deleg_amt: U256,
    pub rewards: U256,
    pub claimable_amount: U256,
    pub apr: Option<f64>,
    pub commission: Option<f64>,
    pub unbonding_period_seconds: Option<u64>,
    pub lst_price_change_percent: Option<f32>,
    pub avg_block_time_ms: Option<u64>,
    pub tag: String,
    pub current_block: Option<u64>,
    pub pending_withdrawals: Vec<PendingWithdrawal>,
}

#[cfg(test)]
mod tests {
    use crate::provider::NetworkProvider;
    use crate::zil::ZilliqaScillaStakeing;

    use proto::address::Address;
    use test_data::gen_zil_mainnet_conf;

    #[tokio::test]
    async fn test_get_scilla_stake() {
        let addr = Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap();

        let net_conf = gen_zil_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let result = provider.fetch_scilla_stake(&addr).await;
        let final_output = result.unwrap();

        println!("{:#?}", final_output);
    }
}
