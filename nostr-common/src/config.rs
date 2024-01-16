use std::fmt;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
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
            local: NostrGenParamsLocal {},
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
pub struct NostrConfigLocal {}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct NostrConfigConsensus {
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrConfigPrivate;

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
