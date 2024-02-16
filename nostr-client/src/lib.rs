use std::collections::{BTreeMap, HashMap};
use std::ffi;

use anyhow::bail;
use common::config::NostrClientConfig;
use common::UnsignedEvent;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{DynModuleApi, FederationApiExt};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiRequestErased, ApiVersion, ModuleCommon, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount};
pub use nostr_common as common;
use nostr_common::{NostrCommonInit, NostrModuleTypes};
use serde_json::json;

pub mod api;
mod db;

#[derive(Debug)]
pub struct NostrClientModule {
    pub cfg: NostrClientConfig,
    pub module_api: DynModuleApi,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct NostrClientContext {
    pub decoder: Decoder,
}

impl Context for NostrClientContext {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for NostrClientModule {
    type Init = NostrClientInit;
    type Common = NostrModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = NostrClientContext;
    type States = NostrClientStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        NostrClientContext {
            decoder: self.decoder(),
        }
    }

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: Amount::ZERO,
            fee: Amount::ZERO,
        })
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: Amount::ZERO,
            fee: Amount::ZERO,
        })
    }

    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        const SUPPORTED_COMMANDS: &str = "sign-event";

        if args.is_empty() {
            bail!("Expected to be called with at least 1 argument: <command> ...");
        }

        let command = args[0].to_string_lossy();

        match command.as_ref() {
            "sign-event" => {
                let pubkey = self.cfg.npub.npub;
                let unsigned_event = UnsignedEvent(
                    nostr_sdk::EventBuilder::new_text_note("FROST".to_string(), &[])
                        .to_unsigned_event(pubkey),
                );
                self.module_api
                    .request_single_peer(
                        None, // no timeout
                        "sign_event".to_string(),
                        ApiRequestErased::new(unsigned_event.clone()),
                        0.into(),
                    )
                    .await?;
                let note_id = format!("{}", unsigned_event.0.id);
                Ok(json!(note_id))
            }
            "help" => {
                let mut map = HashMap::new();
                map.insert("supported_commands", SUPPORTED_COMMANDS);
                Ok(serde_json::to_value(map)?)
            }
            command => {
                bail!("Unknown command: {command}, supported commands: {SUPPORTED_COMMANDS}");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NostrClientInit;

#[apply(async_trait_maybe_send!)]
impl fedimint_core::module::ModuleInit for NostrClientInit {
    type Common = NostrCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for NostrClientInit {
    type Module = NostrClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(NostrClientModule {
            cfg: args.cfg().clone(),
            module_api: args.module_api().clone(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum NostrClientStateMachine {}

impl IntoDynInstance for NostrClientStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for NostrClientStateMachine {
    type ModuleContext = NostrClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        todo!()
    }
}
