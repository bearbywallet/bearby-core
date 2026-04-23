use std::collections::HashMap;

use crate::{
    account::{AccountV1, AccountV2},
    wallet_types::WalletTypes,
};
use config::session::AuthMethod;
use crypto::bip49::DerivationPath;
use crypto::slip44::ETHEREUM;
use errors::wallet::WalletErrors;
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletDataV1 {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    pub accounts: Vec<AccountV1>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
    pub default_chain_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletDataV2 {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    #[serde(default)]
    pub slip44_accounts: HashMap<u32, HashMap<u32, Vec<AccountV2>>>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
    pub chain_hash: u64,
    pub slip44: u32,
    pub bip: u32,
    #[serde(default)]
    pub bip_preferences: HashMap<u32, u32>,
    pub derivation_type: u8,
}

impl From<WalletDataV1> for WalletDataV2 {
    fn from(v1: WalletDataV1) -> Self {
        let slip44 = v1.accounts.first().map(|a| a.slip_44).unwrap_or(ETHEREUM);
        let bip = v1
            .accounts
            .first()
            .map(|acc| acc.addr.get_bip_purpose())
            .unwrap_or(DerivationPath::BIP44_PURPOSE);
        let slip44_accounts: HashMap<u32, HashMap<u32, Vec<AccountV2>>> = HashMap::from([(
            slip44,
            HashMap::from([(bip, v1.accounts.into_iter().map(Into::into).collect())]),
        )]);

        Self {
            slip44_accounts,
            slip44,
            bip,
            proof_key: v1.proof_key,
            wallet_type: v1.wallet_type,
            settings: v1.settings,
            wallet_name: v1.wallet_name,
            selected_account: v1.selected_account,
            biometric_type: v1.biometric_type,
            chain_hash: v1.default_chain_hash,
            bip_preferences: HashMap::new(),
            derivation_type: 0,
        }
    }
}

impl WalletDataV2 {
    pub fn get_selected_account(&self) -> Result<&AccountV2, WalletErrors> {
        self.get_account(self.selected_account)
    }

    pub fn get_account(&self, index: usize) -> Result<&AccountV2, WalletErrors> {
        self.slip44_accounts
            .get(&self.slip44)
            .and_then(|m| m.get(&self.bip))
            .and_then(|accounts| accounts.get(index))
            .ok_or(WalletErrors::InvalidBIPPathIndex(
                self.slip44,
                self.bip,
                index,
            ))
    }

    pub fn get_mut_account(&mut self, index: usize) -> Result<&mut AccountV2, WalletErrors> {
        self.slip44_accounts
            .get_mut(&self.slip44)
            .and_then(|m| m.get_mut(&self.bip))
            .and_then(|accounts| accounts.get_mut(index))
            .ok_or(WalletErrors::InvalidBIPPathIndex(
                self.slip44,
                self.bip,
                index,
            ))
    }

    pub fn get_accounts(&self) -> Result<&[AccountV2], WalletErrors> {
        self.slip44_accounts
            .get(&self.slip44)
            .and_then(|m| m.get(&self.bip))
            .map(|v| v.as_slice())
            .ok_or(WalletErrors::InvalidBIPPath(self.slip44, self.bip))
    }

    pub fn get_mut_accounts(&mut self) -> Result<&mut [AccountV2], WalletErrors> {
        self.slip44_accounts
            .get_mut(&self.slip44)
            .and_then(|m| m.get_mut(&self.bip))
            .map(|v| v.as_mut_slice())
            .ok_or(WalletErrors::InvalidBIPPath(self.slip44, self.bip))
    }

    pub fn remove_account(&mut self, index: usize) {
        for bip_map in self.slip44_accounts.values_mut() {
            for accounts in bip_map.values_mut() {
                accounts.remove(index);
            }
        }
    }
}
