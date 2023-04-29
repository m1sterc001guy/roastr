use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use async_trait::async_trait;
use fedimint_core::config::{
    ClientModuleConfig, ConfigGenModuleParams, DkgResult, ServerModuleConfig,
    ServerModuleConsensusConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ConsensusProposal, CoreConsensusVersion, ExtendsCommonModuleGen,
    InputMeta, ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleGen,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{OutPoint, PeerId, ServerModule};
use fedimint_starter_common::config::{
    StarterConfig, StarterConfigConsensus, StarterConfigPrivate,
};
use fedimint_starter_common::db::migrate_starter_db_version_0;
use fedimint_starter_common::{
    StarterCommonGen, StarterConsensusItem, StarterInput, StarterModuleTypes, StarterOutput,
    StarterOutputOutcome,
};
use futures::FutureExt;

#[derive(Debug, Clone)]
pub struct StarterServerGen;

impl ExtendsCommonModuleGen for StarterServerGen {
    type Common = StarterCommonGen;
}

#[async_trait]
impl ServerModuleGen for StarterServerGen {
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Starter::new(cfg.to_typed()?).into())
    }

    fn get_database_migrations(&self) -> MigrationMap {
        let mut migrations = MigrationMap::new();

        migrations.insert(DatabaseVersion(0), move |dbtx| {
            migrate_starter_db_version_0(dbtx).boxed()
        });

        migrations
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let mint_cfg: BTreeMap<_, StarterConfig> = peers
            .iter()
            .map(|&peer| {
                let config = StarterConfig {
                    private: StarterConfigPrivate {
                        something_private: 3,
                    },
                    consensus: StarterConfigConsensus { something: 1 },
                };
                (peer, config)
            })
            .collect();

        mint_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        _params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let server = StarterConfig {
            private: StarterConfigPrivate {
                something_private: 3,
            },
            consensus: StarterConfigConsensus { something: 2 },
        };

        Ok(server.to_erased())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        Ok(StarterConfigConsensus::from_erased(config)?.to_client_config())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config
            .to_typed::<StarterConfig>()?
            .validate_config(identity)
    }

    async fn dump_database(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

/// Starter module
#[derive(Debug)]
pub struct Starter {
    pub cfg: StarterConfig,
}

#[async_trait]
impl ServerModule for Starter {
    type Common = StarterModuleTypes;
    type Gen = StarterServerGen;
    type VerificationCache = StarterVerificationCache;

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(0, 0, &[(0, 0)])
    }

    async fn await_consensus_proposal(&self, _dbtx: &mut ModuleDatabaseTransaction<'_>) {
        std::future::pending().await
    }

    async fn consensus_proposal(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<StarterConsensusItem> {
        ConsensusProposal::empty()
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, StarterConsensusItem)>,
        _consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId> {
        vec![]
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a StarterInput> + Send,
    ) -> Self::VerificationCache {
        StarterVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a StarterInput,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut ModuleDatabaseTransaction<'c>,
        _input: &'b StarterInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _output: &StarterOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _output: &'a StarterOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &BTreeSet<PeerId>,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<StarterOutputOutcome> {
        None
    }

    async fn audit(&self, _dbtx: &mut ModuleDatabaseTransaction<'_>, _audit: &mut Audit) {}

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "ping",
            async |_module: &Starter, _dbtx, _request: ()| -> String {
                Ok("pong".to_string())
            }
        }]
    }
}

#[derive(Debug, Clone)]
pub struct StarterVerificationCache;

impl fedimint_core::server::VerificationCache for StarterVerificationCache {}

impl Starter {
    /// Create new module instance
    pub fn new(cfg: StarterConfig) -> Starter {
        Starter { cfg }
    }
}
