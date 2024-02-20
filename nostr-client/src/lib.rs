use std::collections::{BTreeMap, HashMap};
use std::ffi;
use std::str::FromStr;
use std::time::Duration;

use anyhow::bail;
use common::config::NostrClientConfig;
use common::{NostrFrost, PublicScalar, UnsignedEvent};
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
use fedimint_core::query::AllOrDeadline;
use fedimint_core::{apply, async_trait_maybe_send, Amount, NumPeers, PeerId};
pub use nostr_common as common;
use nostr_common::{NostrCommonInit, NostrModuleTypes};
use nostr_sdk::EventId;
use schnorr_fun::{frost, Message};
use secp256k1::XOnlyPublicKey;
use serde_json::json;
use sha2::Sha256;

pub mod api;
mod db;

pub struct NostrClientModule {
    pub cfg: NostrClientConfig,
    pub module_api: DynModuleApi,
    pub frost: NostrFrost,
}

impl std::fmt::Debug for NostrClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClientModule").finish()
    }
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
        const SUPPORTED_COMMANDS: &str = "create-note, sign-note";

        if args.is_empty() {
            bail!("Expected to be called with at least 1 argument: <command> ...");
        }

        let command = args[0].to_string_lossy();

        match command.as_ref() {
            "create-note" => {
                if args.len() != 3 {
                    bail!("`create-note` command expects 2 arguments: <text> <peer_id>")
                }

                let text: String = args[1].to_string_lossy().to_string();
                let peer_id: PeerId = args[2].to_string_lossy().parse::<PeerId>()?;

                let pubkey = self.cfg.npub.npub;
                let unsigned_event = UnsignedEvent(
                    nostr_sdk::EventBuilder::new_text_note(text, &[]).to_unsigned_event(pubkey),
                );
                self.module_api
                    .request_single_peer(
                        None, // no timeout
                        "create_note".to_string(),
                        ApiRequestErased::new(unsigned_event.clone()),
                        peer_id,
                    )
                    .await?;
                let note_id = format!("{}", unsigned_event.0.id);
                Ok(json!(note_id))
            }
            "sign-note" => {
                if args.len() != 3 {
                    bail!("`sign-note` command expects 2 arguments: <note-id> <peer_id>")
                }

                let event_id: String = args[1].to_string_lossy().to_string();
                let event_id = EventId::from_str(event_id.as_str())?;
                let peer_id: PeerId = args[2].to_string_lossy().parse::<PeerId>()?;

                self.module_api
                    .request_single_peer(
                        None,
                        "sign_note".to_string(),
                        ApiRequestErased::new(event_id),
                        peer_id,
                    )
                    .await?;

                let threshold = self.cfg.threshold;
                let signing_sessions = self.get_signing_sessions(event_id).await?;
                for (_, signatures) in signing_sessions {
                    if signatures.len() >= threshold as usize {
                        return Ok(json!("Can make a signature!"));
                    }
                }

                Ok(json!("Cannot make a signature yet for {event_id}"))
            }
            "get-sig-shares" => {
                if args.len() != 2 {
                    bail!("`sign-note` command expects 1 argument: <note-id>")
                }

                let event_id: String = args[1].to_string_lossy().to_string();
                let event_id = EventId::from_str(event_id.as_str())?;
                let signing_sessions = self.get_signing_sessions(event_id).await?;
                Ok(json!(signing_sessions))
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

impl NostrClientModule {
    async fn get_signing_sessions(
        &self,
        event_id: EventId,
    ) -> anyhow::Result<BTreeMap<String, BTreeMap<PeerId, PublicScalar>>> {
        let total_peers = self.module_api.all_peers().total();
        let sig_shares: BTreeMap<PeerId, BTreeMap<String, PublicScalar>> = self
            .module_api
            .request_with_strategy(
                AllOrDeadline::new(
                    total_peers,
                    fedimint_core::time::now() + Duration::from_secs(60),
                ),
                "get_sig_shares".to_string(),
                ApiRequestErased::new(event_id),
            )
            .await?;

        let mut signing_sessions: BTreeMap<String, BTreeMap<PeerId, PublicScalar>> =
            BTreeMap::new();

        for (peer_id, inner_map) in sig_shares {
            for (key, value) in inner_map {
                signing_sessions
                    .entry(key)
                    .or_insert_with(BTreeMap::new)
                    .insert(peer_id.clone(), value);
            }
        }

        Ok(signing_sessions)
    }

    fn create_frost_signature(
        &self,
        shares: BTreeMap<PeerId, PublicScalar>,
        frost_key: XOnlyPublicKey,
        event_id: EventId,
    ) {
        let frost_shares = shares
            .into_iter()
            .map(|(_, sig_share)| sig_share.0)
            .collect::<Vec<_>>();
        //let message = Message::raw(event_id.as_bytes());
        //let combined_sig = self.frost.combine_signature_shares(frost_key,
        // session, signature_shares)
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
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
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
