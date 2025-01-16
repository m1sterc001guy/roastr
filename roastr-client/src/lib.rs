use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;
use std::time::{Duration, SystemTime};
use std::{ffi, mem};

use bitcoin::Network;
use fedimint_api_client::api::{self, DynModuleApi, FederationApiExt};
use fedimint_api_client::query::{QueryStep, QueryStrategy};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::config::{ClientModuleConfig, FederationId};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiAuth, ApiRequestErased, ApiVersion, ModuleCommon, MultiApiVersion};
use fedimint_core::time::now;
use fedimint_core::{apply, async_trait_maybe_send, Amount, PeerId};
use nostr_sdk::secp256k1::schnorr::Signature;
use nostr_sdk::{
    Alphabet, Client, JsonUtil, Keys, Kind, Metadata, SingleLetterTag, Tag, TagKind, ToBech32, Url,
};
use roastr_common::endpoint_constants::{
    CREATE_NOTE_ENDPOINT, GET_EVENTS_ENDPOINT, GET_EVENT_ENDPOINT, GET_EVENT_SESSIONS_ENDPOINT,
    GET_NUM_NONCES_ENDPOINT, SIGN_NOTE_ENDPOINT,
};
use roastr_common::{
    peer_id_to_scalar, EventId, Frost, GetUnsignedEventRequest, RoastrCommonInit, RoastrKey,
    RoastrModuleTypes, SignatureShare, SigningSession, UnsignedEvent, KIND,
};
use schnorr_fun::{frost, Message};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::error;

#[cfg(feature = "cli")]
mod cli;
mod db;

pub struct RoastrClientModule {
    pub frost_key: RoastrKey,
    pub module_api: DynModuleApi,
    pub frost: Frost,
    pub admin_auth: Option<ApiAuth>,
    pub nostr_client: Client,
    pub federation_id: FederationId,
    pub client_ctx: ClientContext<Self>,
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

impl Context for RoastrClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

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
    fn input_fee(
        &self,
        _amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        None
    }

    // Roastr module does not support transactions so `output_amount` is not
    // required
    fn output_fee(
        &self,
        _amount: Amount,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        None
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

#[derive(Serialize, Deserialize)]
pub struct BroadcastEventResponse {
    pub federation_npub: String,
    pub event_id: String,
}

impl RoastrClientModule {
    /// Creates a Nostr Text note and proposes it to consensus for signing.
    pub async fn create_note(&self, text: String) -> anyhow::Result<EventId> {
        let public_key = self.frost_key.public_key();
        let unsigned_event =
            UnsignedEvent::new(nostr_sdk::EventBuilder::text_note(text).build(public_key));
        self.request_create_note(unsigned_event).await
    }

    /// Creates a Nostr metadata event and proposes it to consensus for signing
    pub async fn set_metadata(
        &self,
        name: String,
        display_name: String,
        about: String,
        picture: Url,
    ) -> anyhow::Result<EventId> {
        let public_key = self.frost_key.public_key();
        let metadata = Metadata::new()
            .name(name)
            .display_name(display_name)
            .about(about)
            .picture(picture);
        let event = nostr_sdk::EventBuilder::metadata(&metadata).build(public_key);
        self.request_create_note(UnsignedEvent::new(event)).await
    }

    /// Queries the federation for available notes to sign
    pub async fn get_all_notes(&self) -> anyhow::Result<HashMap<EventId, UnsignedEvent>> {
        let admin_auth = self
            .admin_auth
            .clone()
            .ok_or(anyhow::anyhow!("Admin auth not set"))?;
        let notes: HashMap<EventId, UnsignedEvent> = self
            .module_api
            .request_admin(GET_EVENTS_ENDPOINT, ApiRequestErased::default(), admin_auth)
            .await?;
        Ok(notes)
    }

    /// Requests the guardians of the federation to sign the Nostr
    /// `UnsignedEvent`.
    async fn request_create_note(&self, unsigned_event: UnsignedEvent) -> anyhow::Result<EventId> {
        let admin_auth = self
            .admin_auth
            .clone()
            .ok_or(anyhow::anyhow!("Admin auth not set"))?;
        self.module_api
            .request_admin(
                CREATE_NOTE_ENDPOINT,
                ApiRequestErased::new(unsigned_event.clone()),
                admin_auth,
            )
            .await?;
        Ok(unsigned_event.compute_id())
    }

    /// Creates a Federation Announcement Nostr note and proposes it to
    /// consensus for signing.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_federation_announcement(
        &self,
        name: Option<&str>,
        picture: Option<String>,
        about: Option<String>,
        federation_id: FederationId,
        network: Network,
        modules: Vec<String>,
        invite_codes: Vec<String>,
    ) -> anyhow::Result<EventId> {
        let public_key = self.frost_key.public_key();
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

        let d_tag = Tag::identifier(federation_id.to_string());
        let n_tag = Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)),
            vec![network.to_string()],
        );
        let modules_tag = Tag::custom(
            TagKind::custom("modules".to_string()),
            vec![modules.join(",")],
        );
        let u_tags = invite_codes.into_iter().map(|code| {
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
                vec![code],
            )
        });

        let mut tags = vec![d_tag, n_tag, modules_tag];
        tags.extend(u_tags);

        let unsigned_event = UnsignedEvent::new(
            nostr_sdk::EventBuilder::new(Kind::from(38173), metadata.as_json())
                .tags(tags)
                .build(public_key),
        );

        self.request_create_note(unsigned_event).await
    }

    /// Checks the number of signature shares for the note with `event_id`.
    /// Constructs the combined signature and attaches it to the Nostr note.
    /// Finally, the note will be broadcasted to Nostr.
    pub async fn broadcast_note(
        &self,
        event_id: EventId,
    ) -> anyhow::Result<BroadcastEventResponse> {
        let signed_event = self.create_signed_note(event_id).await?;
        self.nostr_client.connect().await;
        self.nostr_client.send_event(signed_event).await?;

        let federation_npub = self.frost_key.public_key().to_bech32()?;

        Ok(BroadcastEventResponse {
            federation_npub,
            event_id: event_id.to_bech32()?,
        })
    }

    /// Creates a signature share for a single peer for the note with
    /// `event_id`.
    pub async fn sign_note(&self, event_id: EventId) -> anyhow::Result<()> {
        let admin_auth = self
            .admin_auth
            .clone()
            .ok_or(anyhow::anyhow!("Admin auth not set"))?;

        // Request the peer to sign the event
        self.module_api
            .request_admin(
                SIGN_NOTE_ENDPOINT,
                ApiRequestErased::new(event_id),
                admin_auth,
            )
            .await?;
        Ok(())
    }

    /// Creates a signed Nostr note by checking if enough signature shares have
    /// been provided by the guardians. If enough signature shares are
    /// available, the combined schnorr signature is created and attached to
    /// the Nostr event.
    pub async fn create_signed_note(&self, event_id: EventId) -> anyhow::Result<nostr_sdk::Event> {
        let threshold = self.frost_key.threshold();
        // Verify that at least a `threshold` number of signature shares have been
        // provided, otherwise we cannot create the signature.
        let signing_sessions = self.get_signing_sessions(event_id).await?;
        for (peers, signatures) in signing_sessions {
            let sorted_peers = peers
                .split(',')
                .map(|peer_id| peer_id.parse::<u16>().expect("Invalid peer id").into())
                .collect::<Vec<PeerId>>();

            if signatures.len() >= threshold {
                let unsigned_event: Option<UnsignedEvent> = self
                    .module_api
                    .request_current_consensus(
                        GET_EVENT_ENDPOINT.to_string(),
                        ApiRequestErased::new(GetUnsignedEventRequest {
                            event_id,
                            signing_session: SigningSession::new(sorted_peers),
                        }),
                    )
                    .await?;

                let unsigned_event =
                    unsigned_event.ok_or(anyhow::anyhow!("Not enough signatures for note"))?;
                let combined = self
                    .create_frost_signature(signatures, &self.frost_key)
                    .ok_or(anyhow::anyhow!("Could not create valid FROST signature"))?;
                let signature = Signature::from_slice(&combined.to_bytes())
                    .expect("Couldn't create nostr signature");
                let signed_event = unsigned_event.add_roast_signature(signature)?;
                return Ok(signed_event);
            }
        }

        Err(anyhow::anyhow!("Not enough signatures for note"))
    }

    /// Queries all peers and retrieves the signing sessions that have been
    /// created in consensus.
    pub async fn get_signing_sessions(
        &self,
        event_id: EventId,
    ) -> anyhow::Result<BTreeMap<String, BTreeMap<PeerId, SignatureShare>>> {
        let sig_shares: BTreeMap<PeerId, BTreeMap<String, SignatureShare>> = self
            .module_api
            .request_with_strategy(
                ThresholdOrDeadline::new(
                    self.module_api.all_peers().len(),
                    now() + Duration::from_secs(2),
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
                    .or_default()
                    .insert(peer_id, value);
            }
        }

        Ok(signing_sessions)
    }

    /// Queries a specific peer for the number of nonces that have been
    /// processed through consensus from other peers.
    pub async fn get_num_nonces(&self) -> anyhow::Result<BTreeMap<PeerId, usize>> {
        let admin_auth = self
            .admin_auth
            .clone()
            .ok_or(anyhow::anyhow!("Admin auth not set"))?;

        // Request the peer to sign the event
        let num_nonces = self
            .module_api
            .request_admin(
                GET_NUM_NONCES_ENDPOINT,
                ApiRequestErased::default(),
                admin_auth,
            )
            .await?;

        Ok(num_nonces)
    }

    /// Creates a combined FROST signature under `frost_key` by combining the
    /// signature `shares` together.
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
                (*sig_share.share.deref()).mark_zero_choice(),
            ) {
                error!(%peer_id, "Signature share failed verification");
                return None;
            }
        }

        let frost_shares = shares
            .clone()
            .into_values()
            .map(|sig_share| sig_share.share.mark_zero_choice())
            .collect::<Vec<_>>();

        // Combine all signature shares into a single schnorr signature.
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

/// Creates a Federation Announcement Nostr note by querying other modules for
/// the necessary data and requests the guardians to sign it.
pub async fn create_federation_announcement(
    roastr: &RoastrClientModule,
    description: Option<String>,
    network: bitcoin::Network,
) -> anyhow::Result<EventId> {
    let federation_id = roastr.federation_id;
    let config = roastr.client_ctx.get_config().await;
    let api_endpoints = config.global.clone().api_endpoints;

    let mut invite_codes = Vec::new();
    for (peer, peer_url) in api_endpoints {
        let invite_code = InviteCode::new(peer_url.url, peer, federation_id, None);
        invite_codes.push(invite_code.to_string());
    }

    let federation_name = config.global.federation_name();

    let module_list: Vec<String> = config
        .modules
        .iter()
        .map(|(_id, ClientModuleConfig { kind, .. })| kind.to_string())
        .collect();
    roastr
        .create_federation_announcement(
            federation_name,
            None,
            description,
            federation_id,
            network,
            module_list,
            invite_codes,
        )
        .await
}

#[derive(Debug, Clone)]
pub struct RoastrClientInit;

impl fedimint_core::module::ModuleInit for RoastrClientInit {
    type Common = RoastrCommonInit;

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
        let frost_key = args.cfg().frost_key.clone();
        let keys = Keys::parse(&frost_key.public_key().to_hex())
            .expect("Could not parse frost public key");
        let nostr_client = Client::builder().signer(keys).build();
        nostr_client.add_relay("wss://nostr.zebedee.cloud").await?;
        nostr_client.add_relay("wss://relay.plebstr.com").await?;
        nostr_client.add_relay("wss://relay.nostr.band").await?;
        nostr_client.add_relay("wss://relayer.fiatjaf.com").await?;
        nostr_client
            .add_relay("wss://nostr-01.bolt.observer")
            .await?;
        nostr_client
            .add_relay("wss://nostr.bitcoiner.social")
            .await?;
        nostr_client
            .add_relay("wss://nostr-relay.wlvs.space")
            .await?;
        nostr_client.add_relay("wss://relay.nostr.info").await?;
        nostr_client
            .add_relay("wss://nostr-pub.wellorder.net")
            .await?;
        nostr_client
            .add_relay("wss://nostr1.tunnelsats.com")
            .await?;
        nostr_client.add_relay("wss://relay.damus.io").await?;
        Ok(RoastrClientModule {
            frost_key,
            module_api: args.module_api().clone(),
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
            admin_auth: args.admin_auth().cloned(),
            nostr_client,
            federation_id: *args.federation_id(),
            client_ctx: args.context(),
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

/// Query strategy that returns when enough peers responded or a deadline passed
pub struct ThresholdOrDeadline<R> {
    deadline: SystemTime,
    threshold: usize,
    responses: BTreeMap<PeerId, R>,
}

impl<R> ThresholdOrDeadline<R> {
    pub fn new(threshold: usize, deadline: SystemTime) -> Self {
        Self {
            deadline,
            threshold,
            responses: BTreeMap::default(),
        }
    }
}

impl<R> QueryStrategy<R, BTreeMap<PeerId, R>> for ThresholdOrDeadline<R> {
    fn process(
        &mut self,
        peer: PeerId,
        result: api::PeerResult<R>,
    ) -> QueryStep<BTreeMap<PeerId, R>> {
        match result {
            Ok(response) => {
                assert!(self.responses.insert(peer, response).is_none());

                if self.threshold <= self.responses.len() || self.deadline <= now() {
                    QueryStep::Success(mem::take(&mut self.responses))
                } else {
                    QueryStep::Continue
                }
            }
            // we rely on retries and timeouts to detect a deadline passing
            Err(_) => {
                if self.deadline <= now() {
                    QueryStep::Success(mem::take(&mut self.responses))
                } else {
                    QueryStep::Retry(BTreeSet::from([peer]))
                }
            }
        }
    }
}
