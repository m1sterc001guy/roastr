use std::collections::BTreeSet;
use std::fmt;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use schnorr_fun::fun::marker::Secret;
use serde::{Deserialize, Serialize};

use crate::{Hash, NostrCommonInit, NostrFrostKey};

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
    pub num_nonces: u32,
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
                num_nonces: std::env::var("NOSTR_NUM_NONCES")
                    .unwrap_or("5".to_string())
                    .parse::<u32>()
                    .expect("NOSTR_NUM_NONCES was not an integer"),
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
pub struct NostrClientConfig {
    pub frost_key: NostrFrostKey,
}

impl fmt::Display for NostrClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrClientConfig")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct NostrConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct NostrConfigConsensus {
    pub all_peers: BTreeSet<PeerId>,
    pub num_nonces: u32,
    // Frost key needs to be last until read_to_end is fixed
    pub frost_key: NostrFrostKey,
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
