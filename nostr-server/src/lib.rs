use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, MigrationMap};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit, PeerHandle,
    ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{OutPoint, PeerId, ServerModule};
use nostr_common::config::{
    NostrClientConfig, NostrConfig, NostrConfigConsensus, NostrConfigLocal, NostrConfigPrivate,
    NostrGenParams,
};
use nostr_common::{
    NostrCommonInit, NostrConsensusItem, NostrInput, NostrInputError, NostrModuleTypes,
    NostrOutput, NostrOutputError, NostrOutputOutcome, CONSENSUS_VERSION,
};
use rand::rngs::OsRng;
use schnorr_fun::frost::Frost;
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256VarCore};

mod db;

type NostrFrost = Frost<
    CoreWrapper<
        CtVariableCoreWrapper<
            Sha256VarCore,
            UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
            OidSha256,
        >,
    >,
    Synthetic<
        CoreWrapper<
            CtVariableCoreWrapper<
                Sha256VarCore,
                UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                OidSha256,
            >,
        >,
        GlobalRng<OsRng>,
    >,
>;

/// Generates the module
#[derive(Clone)]
pub struct NostrInit {
    pub frost: NostrFrost,
}

#[async_trait]
impl ModuleInit for NostrInit {
    type Common = NostrCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
    }
}

impl std::fmt::Debug for NostrInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrInit").finish()
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for NostrInit {
    type Params = NostrGenParams;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Nostr::new(args.cfg().to_typed()?).into())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = NostrConfig {
                    local: NostrConfigLocal {},
                    private: NostrConfigPrivate,
                    consensus: NostrConfigConsensus {},
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();

        Ok(NostrConfig {
            local: NostrConfigLocal {},
            private: NostrConfigPrivate,
            consensus: NostrConfigConsensus {},
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<NostrClientConfig> {
        let _config = NostrConfigConsensus::from_erased(config)?;
        Ok(NostrClientConfig {})
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct Nostr {
    pub cfg: NostrConfig,
}

#[async_trait]
impl ServerModule for Nostr {
    type Common = NostrModuleTypes;
    type Init = NostrInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<NostrConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: NostrConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("The nostr module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b NostrInput,
    ) -> Result<InputMeta, NostrInputError> {
        todo!()
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a NostrOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, NostrOutputError> {
        todo!()
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<NostrOutputOutcome> {
        todo!()
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
        todo!()
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}

impl Nostr {
    /// Create new module instance
    pub fn new(cfg: NostrConfig) -> Nostr {
        Nostr { cfg }
    }
}
