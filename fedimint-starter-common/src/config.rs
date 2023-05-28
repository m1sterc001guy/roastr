use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};

use crate::{CONSENSUS_VERSION, KIND};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarterConfig {
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: StarterConfigPrivate,
    /// Contains all configuration that needs to be the same for every
    /// federation member
    pub consensus: StarterConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct StarterConfigConsensus {
    pub something: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarterConfigPrivate {
    pub something_private: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct StarterClientConfig {
    pub something: u64,
}

impl TypedClientModuleConfig for StarterClientConfig {
    fn kind(&self) -> fedimint_core::core::ModuleKind {
        KIND
    }

    fn version(&self) -> ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}

impl TypedServerModuleConsensusConfig for StarterConfigConsensus {
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(
            KIND,
            CONSENSUS_VERSION,
            &(StarterClientConfig {
                something: self.something,
            }),
        )
        .expect("Serialization can't fail")
    }

    fn kind(&self) -> ModuleKind {
        KIND
    }

    fn version(&self) -> ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}

impl TypedServerModuleConfig for StarterConfig {
    type Local = ();
    type Private = StarterConfigPrivate;
    type Consensus = StarterConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), self.private, self.consensus)
    }

    fn validate_config(&self, _identity: &PeerId) -> anyhow::Result<()> {
        Ok(())
    }
}
