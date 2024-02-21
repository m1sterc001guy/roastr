use std::collections::{BTreeMap, HashMap};
use std::ffi;
use std::str::FromStr;
use std::time::Duration;

use anyhow::bail;
use commands::{
    CREATE_NOTE_COMMAND, GET_EVENT_SESSIONS_COMMAND, HELP_COMMAND, SIGN_NOTE_COMMAND,
    SUPPORTED_COMMANDS,
};
use common::config::NostrFrostKey;
use common::endpoint_constants::{
    CREATE_NOTE_ENDPOINT, GET_EVENT_SESSIONS_ENDPOINT, SIGN_NOTE_ENDPOINT,
};
use common::{peer_id_to_scalar, NostrEventId, NostrFrost, SignatureShare, UnsignedEvent};
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
use fedimint_core::{apply, async_trait_maybe_send, NumPeers, PeerId};
pub use nostr_common as common;
use nostr_common::{NostrCommonInit, NostrModuleTypes};
use schnorr_fun::{frost, Message};
use serde_json::json;
use sha2::Sha256;

mod commands;
mod db;

pub struct NostrClientModule {
    pub frost_key: NostrFrostKey,
    pub module_api: DynModuleApi,
    pub frost: NostrFrost,
}

impl std::fmt::Debug for NostrClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClientModule").finish()
    }
}

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

    // Nostr module does not support transactions so `input_amount` is not required
    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        None
    }

    // Nostr module does not support transactions so `output_amount` is not required
    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        None
    }

    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        if args.is_empty() {
            bail!("Expected to be called with at least 1 argument: <command> ...");
        }

        let command = args[0].to_string_lossy();

        match command.as_ref() {
            CREATE_NOTE_COMMAND => {
                if args.len() != 3 {
                    bail!("`{CREATE_NOTE_COMMAND}` command expects 2 arguments: <text> <peer_id>")
                }

                let text: String = args[1].to_string_lossy().to_string();
                let peer_id: PeerId = args[2].to_string_lossy().parse::<PeerId>()?;

                let event_id = self.create_note(text, peer_id).await?;
                Ok(json!(event_id))
            }
            SIGN_NOTE_COMMAND => {
                if args.len() != 3 {
                    bail!("`{SIGN_NOTE_COMMAND}` command expects 2 arguments: <note-id> <peer_id>")
                }

                let event_id =
                    NostrEventId::from_str(args[1].to_string_lossy().to_string().as_str())?;
                let peer_id: PeerId = args[2].to_string_lossy().parse::<PeerId>()?;
                let signature = self.sign_note(event_id, peer_id).await?;
                Ok(json!(signature))
            }
            GET_EVENT_SESSIONS_COMMAND => {
                if args.len() != 2 {
                    bail!("`{GET_EVENT_SESSIONS_COMMAND}` command expects 1 argument: <note-id>")
                }

                let event_id =
                    NostrEventId::from_str(args[1].to_string_lossy().to_string().as_str())?;
                let signing_sessions = self.get_signing_sessions(event_id).await?;
                Ok(json!(signing_sessions))
            }
            HELP_COMMAND => {
                let mut map = HashMap::new();
                map.insert("supported_commands", SUPPORTED_COMMANDS);
                Ok(serde_json::to_value(map)?)
            }
            command => {
                bail!("Unknown command: {command}, supported commands: {SUPPORTED_COMMANDS:?}");
            }
        }
    }
}

impl NostrClientModule {
    pub async fn create_note(&self, text: String, peer_id: PeerId) -> anyhow::Result<NostrEventId> {
        let pubkey = self
            .frost_key
            .into_frost_key()
            .public_key()
            .to_xonly_bytes();
        let xonly = nostr_sdk::key::XOnlyPublicKey::from_slice(&pubkey)
            .expect("Failed to create xonly public key");
        let unsigned_event = UnsignedEvent::new(
            nostr_sdk::EventBuilder::new_text_note(text, &[]).to_unsigned_event(xonly),
        );
        self.module_api
            .request_single_peer(
                None,
                CREATE_NOTE_ENDPOINT.to_string(),
                ApiRequestErased::new(unsigned_event.clone()),
                peer_id,
            )
            .await?;
        Ok(NostrEventId::new(unsigned_event.id))
    }

    pub async fn sign_note(
        &self,
        event_id: NostrEventId,
        peer_id: PeerId,
    ) -> anyhow::Result<Option<schnorr_fun::Signature>> {
        // Request the peer to sign the event
        self.module_api
            .request_single_peer(
                None,
                SIGN_NOTE_ENDPOINT.to_string(),
                ApiRequestErased::new(event_id),
                peer_id,
            )
            .await?;

        // Check if we can create a signature
        let threshold = self.frost_key.threshold();
        let signing_sessions = self.get_signing_sessions(event_id).await?;
        for (_, signatures) in signing_sessions {
            if signatures.len() >= threshold {
                let combined = self.create_frost_signature(signatures, &self.frost_key);

                return Ok(Some(combined));
            }
        }

        Ok(None)
    }

    async fn get_signing_sessions(
        &self,
        event_id: NostrEventId,
    ) -> anyhow::Result<BTreeMap<String, BTreeMap<PeerId, SignatureShare>>> {
        let total_peers = self.module_api.all_peers().total();
        let sig_shares: BTreeMap<PeerId, BTreeMap<String, SignatureShare>> = self
            .module_api
            .request_with_strategy(
                AllOrDeadline::new(
                    total_peers,
                    fedimint_core::time::now() + Duration::from_secs(60),
                ),
                GET_EVENT_SESSIONS_ENDPOINT.to_string(),
                ApiRequestErased::new(event_id),
            )
            .await?;

        let mut signing_sessions: BTreeMap<String, BTreeMap<PeerId, SignatureShare>> =
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
        shares: BTreeMap<PeerId, SignatureShare>,
        frost_key: &NostrFrostKey,
    ) -> schnorr_fun::Signature {
        let xonly_frost_key = frost_key.into_frost_key().into_xonly_key();
        let unsigned_event = shares
            .clone()
            .into_iter()
            .next()
            .expect("No shares were provided")
            .1
            .unsigned_event;
        let session_nonces = shares
            .clone()
            .into_iter()
            .map(|(peer_id, sig_share)| (peer_id_to_scalar(&peer_id), sig_share.nonce.public()))
            .collect::<BTreeMap<_, _>>();

        let message = Message::raw(unsigned_event.id.as_bytes());
        let session = self
            .frost
            .start_sign_session(&xonly_frost_key, session_nonces, message);

        let frost_shares = shares
            .clone()
            .into_iter()
            .map(|(_, sig_share)| sig_share.share.mark_zero_choice())
            .collect::<Vec<_>>();

        // TODO: Verify each share under the public key

        self.frost
            .combine_signature_shares(&xonly_frost_key, &session, frost_shares)
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
            frost_key: args.cfg().frost_key.clone(),
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
