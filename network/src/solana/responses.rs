use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct RawAccountValue {
    pub data: Vec<String>,
}

const METAPLEX_NAME_MAX: usize = 32;
const METAPLEX_SYMBOL_MAX: usize = 10;

#[derive(Debug)]
pub struct MetaplexMetadata {
    pub name: String,
    pub symbol: String,
}

impl MetaplexMetadata {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let meta_offset = 1 + 32 + 32;
        if data.len() < meta_offset + 4 {
            return None;
        }
        let (name, after_name) = read_padded_string(data, meta_offset, METAPLEX_NAME_MAX)?;
        let (symbol, _) = read_padded_string(data, after_name, METAPLEX_SYMBOL_MAX)?;
        Some(MetaplexMetadata { name, symbol })
    }
}

fn read_padded_string(data: &[u8], offset: usize, max_len: usize) -> Option<(String, usize)> {
    if data.len() < offset + 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    if len > max_len {
        return None;
    }
    let start = offset + 4;
    let end = start + len;
    if data.len() < end {
        return None;
    }
    let s = String::from_utf8_lossy(&data[start..end])
        .trim_matches('\0')
        .to_string();
    Some((s, end))
}

#[derive(Debug, Deserialize)]
pub struct TokenAmount {
    pub amount: String,
}

#[derive(Debug, Deserialize)]
pub struct ParsedTokenAccountInfo {
    #[serde(rename = "tokenAmount")]
    pub token_amount: TokenAmount,
}

#[derive(Debug, Deserialize)]
pub struct ParsedData<T> {
    pub parsed: T,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountValue {
    pub data: ParsedData<ParsedTokenAccountData>,
}

#[derive(Debug, Deserialize)]
pub struct ParsedTokenAccountData {
    pub info: ParsedTokenAccountInfo,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountEntry {
    pub account: TokenAccountValue,
}

#[derive(Debug, Deserialize)]
pub struct MintExtensionEntry {
    pub extension: String,
    pub state: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct MintInfo {
    pub decimals: u8,
    #[serde(default)]
    pub extensions: Vec<MintExtensionEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ParsedMintData {
    pub info: MintInfo,
}

pub fn extract_token2022_metadata(extensions: &[MintExtensionEntry]) -> Option<(String, String)> {
    let state = extensions
        .iter()
        .find(|e| e.extension == "tokenMetadata")?
        .state
        .as_ref()?;
    let name = state.get("name")?.as_str()?.trim_matches('\0').to_string();
    let symbol = state
        .get("symbol")?
        .as_str()?
        .trim_matches('\0')
        .to_string();
    if name.is_empty() && symbol.is_empty() {
        None
    } else {
        Some((name, symbol))
    }
}

#[derive(Debug, Deserialize)]
pub struct AccountInfoValue {
    pub data: ParsedData<ParsedMintData>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaValueResponse<T> {
    pub value: T,
}

#[derive(Debug, Deserialize)]
pub struct BlockhashValue {
    pub blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct SolanaTransactionMeta {
    pub err: Option<Value>,
    pub fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaGetTransactionResult {
    pub meta: Option<SolanaTransactionMeta>,
    pub slot: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaAccountInfo {
    pub owner: String,
    pub space: u64,
}
