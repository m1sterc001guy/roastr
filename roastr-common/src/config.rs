use std::collections::BTreeSet;
use std::fmt;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use schnorr_fun::fun::marker::Secret;
use serde::{Deserialize, Serialize};

use crate::{Hash, RoastrCommonInit, RoastrKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastrGenParams {
    pub local: RoastrGenParamsLocal,
    pub consensus: RoastrGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastrGenParamsLocal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoastrGenParamsConsensus {
    pub threshold: u32,
    pub num_nonces: u32,
}

impl Default for RoastrGenParams {
    fn default() -> Self {
        Self {
            local: RoastrGenParamsLocal,
            consensus: RoastrGenParamsConsensus {
                threshold: std::env::var("ROASTR_THRESHOLD")
                    .unwrap_or("3".to_string())
                    .parse::<u32>()
                    .expect("ROASTR_THRESHOLD was not an integer"),
                num_nonces: std::env::var("ROASTR_NUM_NONCES")
                    .unwrap_or("5".to_string())
                    .parse::<u32>()
                    .expect("ROASTR_NUM_NONCES was not an integer"),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoastrConfig {
    pub local: RoastrConfigLocal,
    pub private: RoastrConfigPrivate,
    pub consensus: RoastrConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct RoastrClientConfig {
    pub frost_key: RoastrKey,
}

impl fmt::Display for RoastrClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.frost_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct RoastrConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoastrConfigConsensus {
    pub all_peers: BTreeSet<PeerId>,
    pub num_nonces: u32,
    // Frost key needs to be last until read_to_end is fixed
    pub frost_key: RoastrKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoastrConfigPrivate {
    pub my_secret_share: schnorr_fun::fun::Scalar<Secret>,
    pub my_peer_id: PeerId,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    RoastrCommonInit,
    RoastrGenParams,
    RoastrGenParamsLocal,
    RoastrGenParamsConsensus,
    RoastrConfig,
    RoastrConfigLocal,
    RoastrConfigPrivate,
    RoastrConfigConsensus,
    RoastrClientConfig
);
