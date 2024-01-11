use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::DynModuleApi;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount};
pub use nostr_common as common;
use nostr_common::{NostrCommonInit, NostrModuleTypes};

pub mod api;
mod db;

#[derive(Debug)]
pub struct NostrClientModule {
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
}

#[derive(Debug, Clone)]
pub struct NostrClientInit;

#[apply(async_trait_maybe_send!)]
impl ModuleInit for NostrClientInit {
    type Common = NostrCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
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
            module_api: args.module_api().clone(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum NostrClientStateMachine {}

impl IntoDynInstance for NostrClientStateMachine {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for NostrClientStateMachine {
    type ModuleContext = NostrClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        todo!()
    }
}
