use std::fmt;
use std::io::ErrorKind;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use schnorr_fun::frost::FrostKey;
use schnorr_fun::fun::marker::{Normal, Secret};
use serde::{Deserialize, Serialize};

use crate::NostrCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrGenParams {
    pub local: NostrGenParamsLocal,
    pub consensus: NostrGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrGenParamsLocal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrGenParamsConsensus {
    pub threshold: u32,
}

impl Default for NostrGenParams {
    fn default() -> Self {
        Self {
            local: NostrGenParamsLocal,
            consensus: NostrGenParamsConsensus {
                threshold: std::env::var("NOSTR_THRESHOLD")
                    .unwrap_or("3".to_string())
                    .parse::<u32>()
                    .expect("NOSTR_THRESHOLD was not an integer"),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrConfig {
    pub local: NostrConfigLocal,
    pub private: NostrConfigPrivate,
    pub consensus: NostrConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct NostrClientConfig {}

impl fmt::Display for NostrClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrClientConfig")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct NostrConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrConfigConsensus {
    pub threshold: u32,
    pub frost_key: FrostKey<Normal>,
}

impl Encodable for NostrConfigConsensus {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let threshold_bytes = self.threshold.to_le_bytes();
        let frost_key_bytes = bincode2::serialize(&self.frost_key).map_err(|_| {
            std::io::Error::new(ErrorKind::Other, "Error serializing FrostKey".to_string())
        })?;
        writer.write(threshold_bytes.as_slice())?;
        writer.write(frost_key_bytes.as_slice())?;
        Ok(threshold_bytes.len() + frost_key_bytes.len())
    }
}

impl Decodable for NostrConfigConsensus {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut threshold_bytes = [0; 4];
        r.read_exact(&mut threshold_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read threshold bytes"))?;
        let threshold = u32::from_le_bytes(threshold_bytes);

        let mut frost_key_bytes = Vec::new();
        r.read_to_end(&mut frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read FrostKey bytes"))?;
        let frost_key = bincode2::deserialize(&frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Failed to deserialize FrostKey"))?;

        Ok(NostrConfigConsensus {
            threshold,
            frost_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrConfigPrivate {
    pub my_secret_share: schnorr_fun::fun::Scalar<Secret>,
    pub my_peer_id: PeerId,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    NostrCommonInit,
    NostrGenParams,
    NostrGenParamsLocal,
    NostrGenParamsConsensus,
    NostrConfig,
    NostrConfigLocal,
    NostrConfigPrivate,
    NostrConfigConsensus,
    NostrClientConfig
);
