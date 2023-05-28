use std::fmt;

use async_trait::async_trait;
use fedimint_core::config::ModuleGenParams;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleGen, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod config;
pub mod db;

const KIND: ModuleKind = ModuleKind::from_static_str("starter");
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StarterConsensusItem;

#[derive(Debug)]
pub struct StarterCommonGen;

#[async_trait]
impl CommonModuleGen for StarterCommonGen {
    const KIND: ModuleKind = KIND;

    fn decoder() -> Decoder {
        StarterModuleTypes::decoder_builder().build()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarterConfigGenParams {
    pub important_param: u64,
}

impl ModuleGenParams for StarterConfigGenParams {}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct StarterInput;

impl fmt::Display for StarterInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StarterInput")
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct StarterOutput;

impl fmt::Display for StarterOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StarterOutput")
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct StarterOutputOutcome;

impl fmt::Display for StarterOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StarterOutputOutcome")
    }
}

impl fmt::Display for StarterConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StarterOutputConfirmation")
    }
}

pub struct StarterModuleTypes;

impl ModuleCommon for StarterModuleTypes {
    type Input = StarterInput;
    type Output = StarterOutput;
    type OutputOutcome = StarterOutputOutcome;
    type ConsensusItem = StarterConsensusItem;
}

plugin_types_trait_impl_common!(
    StarterInput,
    StarterOutput,
    StarterOutputOutcome,
    StarterConsensusItem
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum StarterError {
    #[error("Something went wrong")]
    SomethingStarterWentWrong,
}
