use std::collections::{BTreeMap, HashMap};
use std::ffi;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use anyhow::bail;
use commands::{
    CREATE_NOTE_COMMAND, GET_EVENT_SESSIONS_COMMAND, HELP_COMMAND, SIGN_NOTE_COMMAND,
    SUPPORTED_COMMANDS,
};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{DynModuleApi, FederationApiExt};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiRequestErased, ApiVersion, ModuleCommon, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::query::ThresholdOrDeadline;
use fedimint_core::{apply, async_trait_maybe_send, NumPeersExt, PeerId};
use nostr_sdk::{Alphabet, JsonUtil, Kind, SingleLetterTag, Tag, TagKind, Url};
use roastr_common::endpoint_constants::{
    CREATE_NOTE_ENDPOINT, GET_EVENT_SESSIONS_ENDPOINT, SIGN_NOTE_ENDPOINT,
};
use roastr_common::{
    peer_id_to_scalar, EventId, Frost, RoastrCommonInit, RoastrKey, RoastrModuleTypes,
    SignatureShare, UnsignedEvent,
};
use schnorr_fun::{frost, Message};
use serde_json::json;
use sha2::Sha256;
use tracing::error;

mod commands;
mod db;

pub struct RoastrClientModule {
    pub frost_key: RoastrKey,
    pub module_api: DynModuleApi,
    pub frost: Frost,
}

impl std::fmt::Debug for RoastrClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoastrClientModule")
            .field("frost_key", &self.frost_key)
            .field("module_api", &self.module_api)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RoastrClientContext {
    pub decoder: Decoder,
}

impl Context for RoastrClientContext {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for RoastrClientModule {
    type Init = RoastrClientInit;
    type Common = RoastrModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = RoastrClientContext;
    type States = RoastrClientStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        RoastrClientContext {
            decoder: self.decoder(),
        }
    }

    // Roastr module does not support transactions so `input_amount` is not required
    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        None
    }

    // Roastr module does not support transactions so `output_amount` is not
    // required
    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        None
    }

    // TODO: Use Clap
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

                let event_id = EventId::from_str(args[1].to_string_lossy().to_string().as_str())?;
                let peer_id: PeerId = args[2].to_string_lossy().parse::<PeerId>()?;
                let signature = self.sign_note(event_id, peer_id).await?;
                Ok(json!(signature))
            }
            GET_EVENT_SESSIONS_COMMAND => {
                if args.len() != 2 {
                    bail!("`{GET_EVENT_SESSIONS_COMMAND}` command expects 1 argument: <note-id>")
                }

                let event_id = EventId::from_str(args[1].to_string_lossy().to_string().as_str())?;
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

impl RoastrClientModule {
    pub async fn create_note(&self, text: String, peer_id: PeerId) -> anyhow::Result<EventId> {
        let pubkey = self
            .frost_key
            .into_frost_key()
            .public_key()
            .to_xonly_bytes();
        let nostr_pubkey = nostr_sdk::PublicKey::from_slice(&pubkey)
            .expect("Failed to create public key from frost key");
        let unsigned_event = UnsignedEvent::new(
            nostr_sdk::EventBuilder::text_note(text, []).to_unsigned_event(nostr_pubkey),
        );
        self.module_api
            .request_single_peer(
                None,
                CREATE_NOTE_ENDPOINT.to_string(),
                ApiRequestErased::new(unsigned_event.clone()),
                peer_id,
            )
            .await?;
        Ok(unsigned_event.compute_id())
    }

    pub async fn create_federation_announcement(
        &self,
        name: Option<String>,
        picture: Option<String>,
        about: Option<String>,
        peer_id: PeerId,
    ) -> anyhow::Result<EventId> {
        let pubkey = self
            .frost_key
            .into_frost_key()
            .public_key()
            .to_xonly_bytes();
        let public_key =
            nostr_sdk::PublicKey::from_slice(&pubkey).expect("Failed to create xonly public key");
        let metadata = {
            let mut m = nostr_sdk::nostr::Metadata::default();
            if let Some(name) = name {
                m = m.name(name);
            }
            if let Some(picture) = picture {
                m = m.picture(Url::parse(&picture)?);
            }
            if let Some(about) = about {
                m = m.about(about);
            }
            m
        };

        // todo figure out how to get federation_id
        let d_tag = Tag::Identifier("federation_id".to_string());
        // todo get network
        let n_tag = Tag::Generic(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)),
            vec!["signet".to_string()],
        );
        // todo get other modules
        let modules_tag = Tag::Generic(
            TagKind::Custom("modules".to_string()),
            vec!["mint,lightning,wallet,nostr".to_string()],
        );
        // todo get all invite codes
        let invite_codes = vec!["fed11abc...".to_string(), "fed11xyz...".to_string()];
        let u_tags = invite_codes.into_iter().map(|code| {
            Tag::Generic(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
                vec![code],
            )
        });

        let mut tags = vec![d_tag, n_tag, modules_tag];
        tags.extend(u_tags);

        let unsigned_event = UnsignedEvent::new(
            nostr_sdk::EventBuilder::new(Kind::from(38173), metadata.as_json(), tags)
                .to_unsigned_event(public_key.into()),
        );

        self.module_api
            .request_single_peer(
                None,
                CREATE_NOTE_ENDPOINT.to_string(), /* we don't need to create a new endpoint for
                                                   * this */
                ApiRequestErased::new(unsigned_event.clone()),
                peer_id,
            )
            .await?;

        Ok(unsigned_event.compute_id())
    }

    pub async fn sign_note(
        &self,
        event_id: EventId,
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
                return Ok(combined);
            }
        }

        Ok(None)
    }

    async fn get_signing_sessions(
        &self,
        event_id: EventId,
    ) -> anyhow::Result<BTreeMap<String, BTreeMap<PeerId, SignatureShare>>> {
        let total_peers = self.module_api.all_peers().total();
        let sig_shares: BTreeMap<PeerId, BTreeMap<String, SignatureShare>> = self
            .module_api
            .request_with_strategy(
                ThresholdOrDeadline::new(
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
        frost_key: &RoastrKey,
    ) -> Option<schnorr_fun::Signature> {
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

        let event_id = unsigned_event.compute_id();
        let message = Message::raw(event_id.as_bytes());
        let session = self
            .frost
            .start_sign_session(&xonly_frost_key, session_nonces, message);

        // Verify each signature share is valid
        for (peer_id, sig_share) in shares.clone().into_iter() {
            let curr_index = peer_id_to_scalar(&peer_id);
            if !self.frost.verify_signature_share(
                &xonly_frost_key,
                &session,
                curr_index,
                sig_share.share.deref().clone().mark_zero_choice(),
            ) {
                error!(%peer_id, "Signature share failed verification");
                return None;
            }
        }

        let frost_shares = shares
            .clone()
            .into_iter()
            .map(|(_, sig_share)| sig_share.share.mark_zero_choice())
            .collect::<Vec<_>>();

        let combined_sig =
            self.frost
                .combine_signature_shares(&xonly_frost_key, &session, frost_shares);

        if !self
            .frost
            .schnorr
            .verify(&xonly_frost_key.public_key(), message, &combined_sig)
        {
            error!(%combined_sig, "Schnorr signature verification failed");
            return None;
        }

        Some(combined_sig)
    }
}

#[derive(Debug, Clone)]
pub struct RoastrClientInit;

#[apply(async_trait_maybe_send!)]
impl fedimint_core::module::ModuleInit for RoastrClientInit {
    type Common = RoastrCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new([].into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for RoastrClientInit {
    type Module = RoastrClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(RoastrClientModule {
            frost_key: args.cfg().frost_key.clone(),
            module_api: args.module_api().clone(),
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Hash)]
pub enum RoastrClientStateMachine {}

impl IntoDynInstance for RoastrClientStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for RoastrClientStateMachine {
    type ModuleContext = RoastrClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        OperationId::new_random()
    }
}
