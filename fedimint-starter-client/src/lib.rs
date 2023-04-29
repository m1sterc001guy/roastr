pub mod api;

use std::ffi;

use api::StarterFederationApi;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientOutput;
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::api::IFederationApi;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_starter_common::config::StarterClientConfig;
pub use fedimint_starter_common::*;

#[derive(Debug, Clone)]
pub struct StarterClientGen;

impl ExtendsCommonModuleGen for StarterClientGen {
    type Common = StarterCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for StarterClientGen {
    type Module = StarterClientModule;
    type Config = StarterClientConfig;

    async fn init(
        &self,
        _cfg: Self::Config,
        _db: Database,
        _module_root_secret: DerivableSecret,
        _notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        Ok(StarterClientModule {})
    }
}

#[derive(Debug)]
pub struct StarterClientModule {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for StarterClientModule {
    type Common = StarterModuleTypes;
    type ModuleStateMachineContext = ();
    type States = StarterClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {}

    async fn handle_cli_command(
        &self,
        client: &Client,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        if args.len() < 1 {
            return Err(anyhow::format_err!(
                "Expected to be called with at least 1 arguments: <command> …"
            ));
        }

        let command = args[0].to_string_lossy();

        match command.as_ref() {
            "ping" => {
                let api = client.api();
                let result = api.ping().await?;
                Ok(serde_json::to_value(result).unwrap())
            }
            command => Err(anyhow::format_err!(
                "Unknown command: {command}, supported commands: ping"
            )),
        }
    }

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> TransactionItemAmount {
        unimplemented!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        unimplemented!()
    }
}

impl StarterClientModule {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice
    /// for us. It has time till the block height defined by `timelock`,
    /// after that we can claim our money back.
    pub async fn ping<'a>(
        &'a self,
        api: &(dyn IFederationApi + 'static),
    ) -> anyhow::Result<String> {
        Ok(api.ping().await?)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum StarterClientStates {}

impl IntoDynInstance for StarterClientStates {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for StarterClientStates {
    type ModuleContext = ();
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        unimplemented!()
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!()
    }
}
