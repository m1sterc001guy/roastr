use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;

use anyhow::anyhow;
use async_trait::async_trait;
use db::{
    NonceKey, NoncePeerPrefix, SessionNonceKey, SessionNoncePrefix, SignatureShareEventPrefix,
};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, CoreConsensusVersion, IDynCommonModuleInit, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{push_db_pair_items, OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use fedimint_server::net::api::check_auth;
use futures::StreamExt;
use itertools::Itertools;
use rand::rngs::OsRng;
use roastr_common::config::{
    RoastrClientConfig, RoastrConfig, RoastrConfigConsensus, RoastrConfigLocal,
    RoastrConfigPrivate, RoastrGenParams,
};
use roastr_common::endpoint_constants::{
    CREATE_NOTE_ENDPOINT, GET_EVENTS_ENDPOINT, GET_EVENT_ENDPOINT, GET_EVENT_SESSIONS_ENDPOINT,
    GET_NUM_NONCES_ENDPOINT, SIGN_NOTE_ENDPOINT,
};
use roastr_common::{
    peer_id_to_scalar, EventId, Frost, GetUnsignedEventRequest, NonceKeyPair, Point, PublicScalar,
    RoastrCommonInit, RoastrConsensusItem, RoastrInput, RoastrInputError, RoastrKey,
    RoastrModuleTypes, RoastrOutcome, RoastrOutput, RoastrOutputError, SecretScalar, Signature,
    SignatureShare, SigningSession, UnsignedEvent, KIND, MODULE_CONSENSUS_VERSION,
};
use schnorr_fun::fun::poly;
use schnorr_fun::Message;
use strum::IntoEnumIterator;
use tracing::{error, info};

use crate::db::{DbKeyPrefix, NoncePrefix, SessionNonces, SignatureShareKey, SignatureSharePrefix};

mod db;

/// Generates the module
#[derive(Clone)]
pub struct RoastrInit {
    pub frost: Frost,
}

impl ModuleInit for RoastrInit {
    type Common = RoastrCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Nonce => {
                    push_db_pair_items!(dbtx, NoncePrefix, NonceKey, (), items, "Nonces");
                }
                DbKeyPrefix::SessionNonces => {
                    push_db_pair_items!(
                        dbtx,
                        SessionNoncePrefix,
                        SessionNonceKey,
                        SessionNonces,
                        items,
                        "Session Nonces"
                    );
                }
                DbKeyPrefix::SignatureShare => {
                    push_db_pair_items!(
                        dbtx,
                        SignatureSharePrefix,
                        SignatureShareKey,
                        SignatureShare,
                        items,
                        "Signature Share"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

impl std::fmt::Debug for RoastrInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoastrInit").finish()
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for RoastrInit {
    type Params = RoastrGenParams;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Roastr::new(args.cfg().to_typed()?, self.frost.clone()).into())
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let threshold = params.consensus.threshold;

        let shares = self
            .frost
            .simulate_keygen(threshold as usize, peers.len(), &mut OsRng);
        let all_peers = BTreeSet::from_iter(peers.iter().cloned());

        peers
            .iter()
            .map(|peer_id| {
                let secret_share = shares
                    .1
                    .get(&peer_id_to_scalar(peer_id))
                    .expect("No secret share for peer during trusted setup");
                let config = RoastrConfig {
                    local: RoastrConfigLocal,
                    private: RoastrConfigPrivate {
                        my_peer_id: *peer_id,
                        my_secret_share: *secret_share,
                    },
                    consensus: RoastrConfigConsensus {
                        num_nonces: params.consensus.num_nonces,
                        frost_key: RoastrKey::new(shares.clone().0.into()),
                        all_peers: all_peers.clone(),
                    },
                }
                .to_erased();

                (*peer_id, config)
            })
            .collect::<BTreeMap<PeerId, ServerModuleConfig>>()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let threshold = params.consensus.threshold;

        // Generate our own polynomial
        let my_secret_poly = poly::scalar::generate(threshold as usize, &mut OsRng);
        let my_public_poly = poly::scalar::to_point_poly(&my_secret_poly)
            .iter()
            .map(|point| Point::new(*point))
            .collect::<Vec<_>>();

        // Exchange our polynomial with the other peers and wait for the polynomials
        // from the other peers.
        let public_polynomials = peers
            .exchange_with_peers::<Vec<Point>>(
                "nostr_polynomials".to_string(),
                my_public_poly,
                KIND,
                self.decoder(),
            )
            .await?
            .into_iter()
            .map(|(peer_id, poly)| {
                (
                    peer_id_to_scalar(&peer_id),
                    poly.into_iter()
                        .map(|point| *point.deref())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let my_index = peer_id_to_scalar(&peers.our_id);
        let my_polys = BTreeMap::from_iter([(my_index, &my_secret_poly)]);

        // Start FROST key generation
        let keygen = self
            .frost
            .new_keygen(public_polynomials, &my_polys)
            .expect("Something went wrong with what was provided by the other parties");

        // Create our shares and proof of possession to send to the other peers.
        let keygen_id = self.frost.keygen_id(&keygen);
        let pop_message = Message::raw(&keygen_id);
        let (shares_i_generated, pop) =
            self.frost
                .create_shares_and_pop(&keygen, &my_secret_poly, pop_message);

        // Map the generated shares to structs that are Encodable/Decodable
        let shares_i_generated_converted = shares_i_generated
            .into_iter()
            .map(|(public, secret)| (PublicScalar::new(public), SecretScalar::new(secret)))
            .collect::<BTreeMap<_, _>>();

        // Exchanges the shares and pops with all peers
        let shares_and_pop: BTreeMap<PeerId, FrostShare> = peers
            .exchange_with_peers::<FrostShare>(
                "nostr_shares".to_string(),
                (shares_i_generated_converted, Signature::new(pop)),
                KIND,
                self.decoder(),
            )
            .await?;

        // Aggregate the shares that were sent from other peers into just the shares
        // that were sent for this peer.
        let my_shares = shares_and_pop
            .iter()
            .map(|(peer, shares_from_peer)| {
                let index = peer_id_to_scalar(peer);
                (
                    index,
                    (
                        *shares_from_peer
                            .0
                            .get(&PublicScalar::new(my_index))
                            .expect("Didnt find our share")
                            .deref(),
                        shares_from_peer.1.deref().clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        // Finish the key generation process. Yields a `FrostKey` and a secret share
        // that this peer can sign with.
        let (my_secret_share, frost_key) = self
            .frost
            .finish_keygen(keygen.clone(), my_index, my_shares, pop_message)
            .expect("Finish keygen failed");

        tracing::info!(?peers.our_id, "DKG Finished successfully");

        let all_peers = BTreeSet::from_iter(peers.peer_ids().iter().cloned());

        Ok(RoastrConfig {
            local: RoastrConfigLocal,
            private: RoastrConfigPrivate {
                my_peer_id: peers.our_id,
                my_secret_share,
            },
            consensus: RoastrConfigConsensus {
                num_nonces: params.consensus.num_nonces,
                frost_key: RoastrKey::new(frost_key.into()),
                all_peers,
            },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<RoastrClientConfig> {
        let config = RoastrConfigConsensus::from_erased(config)?;
        Ok(RoastrClientConfig {
            frost_key: config.frost_key,
        })
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct Roastr {
    cfg: RoastrConfig,
    frost: Frost,
}

impl std::fmt::Debug for Roastr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Roastr").field("cfg", &self.cfg).finish()
    }
}

#[async_trait]
impl ServerModule for Roastr {
    type Common = RoastrModuleTypes;
    type Init = RoastrInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<RoastrConsensusItem> {
        let num_nonces = self.cfg.consensus.num_nonces;

        let mut consensus_items = Vec::new();

        // Query the database to see if we have enough nonces
        let my_peer_id = self.cfg.private.my_peer_id;
        let nonces = dbtx
            .find_by_prefix(&NoncePeerPrefix {
                peer_id: my_peer_id,
            })
            .await
            .collect::<Vec<_>>()
            .await;

        // Propose a nonce consensus item if we are below the pre-configured threshold
        // number of nonces
        if nonces.len() < num_nonces as usize {
            let nonce = NonceKeyPair::new(schnorr_fun::musig::NonceKeyPair::random(
                &mut rand::rngs::OsRng,
            ));
            consensus_items.push(RoastrConsensusItem::Nonce(Box::new(nonce)));
        }

        // Query for signing sessions that have no nonces selected
        let signing_sessions = dbtx
            .find_by_prefix(&SessionNoncePrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        // TODO: These signing sessions need to be deleted.
        for (session_key, session) in signing_sessions {
            // An empty signing session indicates that it was requested from this peer and
            // should be broadcasted to the other peers.
            if session.nonces.is_empty() {
                consensus_items.push(RoastrConsensusItem::SigningSession((
                    session.unsigned_event,
                    session_key.signing_session,
                )));
            }
        }

        consensus_items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: RoastrConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            RoastrConsensusItem::Nonce(nonce) => {
                let nonces = dbtx
                    .find_by_prefix(&NoncePeerPrefix { peer_id })
                    .await
                    .collect::<Vec<_>>()
                    .await;
                let num_nonces = self.cfg.consensus.num_nonces;

                // Ignore any nonces that are beyond the threshold
                if nonces.len() >= num_nonces as usize {
                    return Ok(());
                }

                dbtx.insert_new_entry(
                    &NonceKey {
                        peer_id,
                        nonce: *nonce,
                    },
                    &(),
                )
                .await;

                let num_nonces = dbtx
                    .find_by_prefix(&NoncePeerPrefix { peer_id })
                    .await
                    .collect::<Vec<_>>()
                    .await
                    .len();

                let my_peer_id = self.cfg.private.my_peer_id;
                tracing::info!(
                    ?my_peer_id,
                    ?peer_id,
                    ?num_nonces,
                    "Processed Nonce Consensus Item"
                );
            }
            RoastrConsensusItem::SigningSession((unsigned_event, signing_session)) => {
                let event_id = unsigned_event.compute_id();
                let previous_session = dbtx
                    .get_value(&SessionNonceKey {
                        event_id,
                        signing_session: signing_session.clone(),
                    })
                    .await;
                if previous_session.is_some()
                    && !previous_session.expect("already checked").nonces.is_empty()
                {
                    return Ok(());
                }

                // Deterministically dequeue the nonces from the pre-prepared list and assign
                // them to this signing session
                let my_peer_id = self.cfg.private.my_peer_id;
                match self.dequeue_nonces(dbtx, &signing_session).await {
                    Ok(nonces) => {
                        tracing::info!(
                            ?my_peer_id,
                            ?peer_id,
                            ?signing_session,
                            ?event_id,
                            "Inserting nonces into signing session"
                        );
                        dbtx.insert_entry(
                            &SessionNonceKey {
                                event_id,
                                signing_session: signing_session.clone(),
                            },
                            &SessionNonces {
                                nonces: nonces.clone(),
                                unsigned_event: unsigned_event.clone(),
                            },
                        )
                        .await;

                        // If this signing session was submitted by ourself, we should also create a
                        // signature share
                        if peer_id == my_peer_id {
                            tracing::info!(
                                ?my_peer_id,
                                ?signing_session,
                                ?event_id,
                                "Creating signature share"
                            );
                            let sig_share =
                                self.create_sig_share(unsigned_event.clone(), nonces).await;
                            dbtx.insert_new_entry(
                                &SignatureShareKey {
                                    event_id,
                                    signing_session,
                                },
                                &sig_share,
                            )
                            .await;
                        }
                    }
                    Err(err) => {
                        // Delete the signing session if we cannot find nonces so we don't keep
                        // proposing the same signing session when a node is offline.
                        dbtx.remove_entry(&SessionNonceKey {
                            event_id,
                            signing_session: signing_session.clone(),
                        })
                        .await;

                        tracing::warn!(
                            ?my_peer_id,
                            ?signing_session,
                            ?event_id,
                            "Could not process signing session: {err}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Roastr module does not support transactions so no inputs need to be
    /// processed.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b RoastrInput,
    ) -> Result<InputMeta, RoastrInputError> {
        Err(RoastrInputError::InvalidOperation(
            "Roastr module does not process inputs".to_string(),
        ))
    }

    /// Roastr module does not support transactions so no outputs need to be
    /// processed.
    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a RoastrOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, RoastrOutputError> {
        Err(RoastrOutputError::InvalidOperation(
            "Roastr module does not process output".to_string(),
        ))
    }

    /// Roastr module does not support transactions so there are no outputs.
    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<RoastrOutcome> {
        None
    }

    /// Roastr module does not support transactions so auditing is not necessary
    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                CREATE_NOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Roastr, context, unsigned_event: UnsignedEvent| -> () {
                    check_auth(context)?;

                    let mut dbtx = context.dbtx();
                    let event_id = unsigned_event.compute_id();
                    let my_peer_id = module.cfg.private.my_peer_id;
                    let sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    for signing_session in sign_session_iter {
                        info!(?my_peer_id, ?signing_session, ?event_id, "Creating signing session...");
                        dbtx.insert_new_entry(&SessionNonceKey { event_id, signing_session }, &SessionNonces::new(unsigned_event.clone())).await;
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                SIGN_NOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Roastr, context, event_id: EventId| -> () {
                    check_auth(context)?;

                    let mut dbtx = context.dbtx();

                    let my_peer_id = module.cfg.private.my_peer_id;
                    let sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    for sign_session in sign_session_iter {
                        module.sign_note_or_start_sign_session(&mut dbtx.to_ref_nc(), sign_session.clone(), event_id).await;
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                GET_EVENT_SESSIONS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Roastr, context, event_id: EventId| -> BTreeMap<String, SignatureShare> {

                    let mut dbtx = context.dbtx();

                    let signatures = dbtx
                        .find_by_prefix(&SignatureShareEventPrefix { event_id })
                        .await
                        .map(|(key, sig_share)| {
                            (key.signing_session.to_string(), sig_share)
                        })
                        .collect::<BTreeMap<_, _>>()
                        .await;

                    Ok(signatures)
                }
            },
            api_endpoint! {
                GET_EVENT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Roastr, context, event_request: GetUnsignedEventRequest| -> Option<UnsignedEvent> {
                    let mut dbtx = context.dbtx();
                    let session_nonce_key = SessionNonceKey { signing_session: event_request.signing_session, event_id: event_request.event_id };
                    let session_nonces = dbtx.get_value(&session_nonce_key).await;
                    match session_nonces {
                        Some(nonces) => Ok(Some(nonces.unsigned_event)),
                        None => Ok(None),
                    }
                }
            },
            api_endpoint! {
                GET_NUM_NONCES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |roastr: &Roastr, context, _v: ()| -> BTreeMap<PeerId, usize> {
                    check_auth(context)?;
                    let mut dbtx = context.dbtx();

                    let all_peers = roastr.cfg.consensus.all_peers.clone();

                    let mut nonces = BTreeMap::new();
                    for peer_id in all_peers {
                        let num_nonces = dbtx
                            .find_by_prefix(&NoncePeerPrefix { peer_id })
                            .await
                            .collect::<Vec<_>>()
                            .await
                            .len();
                        nonces.insert(peer_id, num_nonces);
                    }

                    Ok(nonces)
                }
            },
            api_endpoint! {
                GET_EVENTS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |roastr: &Roastr, context, _v: ()| -> HashMap<EventId, UnsignedEvent> {
                    check_auth(context)?;
                    let mut dbtx = context.dbtx();
                    let events = roastr.get_all_events(&mut dbtx.to_ref_nc()).await;
                    Ok(events)
                }
            },
        ]
    }
}

impl Roastr {
    pub fn new(cfg: RoastrConfig, frost: Frost) -> Roastr {
        Roastr { cfg, frost }
    }

    /// Checks if any signing session exists for the `event_id`. If no session
    /// exists, None is returned. If an existing signing session does exist,
    /// the `UnsignedEvent` is returned.
    async fn get_unsigned_event_for_id(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        event_id: EventId,
    ) -> Option<UnsignedEvent> {
        let unsigned_events = dbtx
            .find_by_prefix(&SessionNoncePrefix)
            .await
            .filter_map(|(session_key, session_nonce)| async move {
                if session_key.event_id == event_id {
                    Some(session_nonce.unsigned_event)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .await;

        unsigned_events.into_iter().next()
    }

    /// Creates a signature share for the current peer or starts a new signing
    /// session if it doesn't exist.
    async fn sign_note_or_start_sign_session(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_session: SigningSession,
        event_id: EventId,
    ) {
        let session_nonces = dbtx
            .get_value(&SessionNonceKey {
                signing_session: signing_session.clone(),
                event_id,
            })
            .await;
        if let Some(session_nonces) = session_nonces {
            // Check if a signature share for this session already exists
            if dbtx
                .get_value(&SignatureShareKey {
                    signing_session: signing_session.clone(),
                    event_id,
                })
                .await
                .is_some()
            {
                tracing::warn!(
                    ?event_id,
                    ?signing_session,
                    "Signature Share already exists. Nothing to do."
                );
                return;
            }

            tracing::info!(?event_id, ?signing_session, "Creating signature share...");
            let sig_share = self
                .create_sig_share(session_nonces.unsigned_event.clone(), session_nonces.nonces)
                .await;

            dbtx.insert_entry(
                &SignatureShareKey {
                    signing_session: signing_session.clone(),
                    event_id,
                },
                &sig_share,
            )
            .await;
        } else {
            // No signing session exists, create a new one
            if let Some(unsigned_event) = self.get_unsigned_event_for_id(dbtx, event_id).await {
                dbtx.insert_new_entry(
                    &SessionNonceKey {
                        event_id,
                        signing_session,
                    },
                    &SessionNonces::new(unsigned_event.clone()),
                )
                .await;
            } else {
                error!(?event_id, "No signing session exists for this event");
            }
        }
    }

    /// For a given `SigningSession`, iterate through the peers and dequeue the
    /// next nonce from the pre-prepared list.
    async fn dequeue_nonces(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_session: &SigningSession,
    ) -> anyhow::Result<BTreeMap<PeerId, NonceKeyPair>> {
        let mut nonces = BTreeMap::new();
        let peers_iter = signing_session.clone();
        for peer_id in peers_iter {
            // Always use the first available nonce for the peer
            let (nonce_key, _) = match dbtx
                .find_by_prefix(&NoncePeerPrefix { peer_id })
                .await
                .next()
                .await
            {
                Some(nonce) => nonce,
                None => {
                    return Err(anyhow!("Not enough nonces for peer: {peer_id}"));
                }
            };

            nonces.insert(nonce_key.peer_id, nonce_key.nonce.clone());

            // remove the nonce from the database
            dbtx.remove_entry(&nonce_key).await;
        }

        Ok(nonces)
    }

    /// Creates a signature share for the `UnsignedEvent` and the given nonces.
    async fn create_sig_share(
        &self,
        unsigned_event: UnsignedEvent,
        nonces: BTreeMap<PeerId, NonceKeyPair>,
    ) -> SignatureShare {
        let frost_key = self.cfg.consensus.frost_key.clone();
        let xonly_frost_key = frost_key.into_frost_key().into_xonly_key();

        // Nostr events are always signed by their id
        let event_id = unsigned_event.compute_id();
        let message_raw = Message::raw(event_id.as_bytes());

        // Prepare the nonces to be used for this signing session by mapping the
        // `PeerId` to `Scalar<Public, NonZero>` and `NonceKeyPair` to `Nonce`
        let session_nonces = nonces
            .clone()
            .into_iter()
            .map(|(peer, nonce_pair)| (peer_id_to_scalar(&peer), nonce_pair.public()))
            .collect::<BTreeMap<_, _>>();

        // Start the FROST signing session with the prepared nonces
        let session = self
            .frost
            .start_sign_session(&xonly_frost_key, session_nonces, message_raw);

        // Using our secret share created during DKG, create our contribution to the
        // FROST signature.
        let my_secret_share = self.cfg.private.my_secret_share;
        let my_index = &self.cfg.private.my_peer_id;
        let my_nonce = nonces
            .get(my_index)
            .expect("This peer did not contribute a nonce. This should never happen, we should only create signature shares for sessions we are apart of.")
            .clone();
        let my_sig_share = self.frost.sign(
            &xonly_frost_key,
            &session,
            peer_id_to_scalar(my_index),
            &my_secret_share,
            my_nonce.deref().clone(),
        );

        SignatureShare {
            share: PublicScalar::new(my_sig_share.non_zero().expect("Signature share was zero")),
            nonce: my_nonce,
            unsigned_event,
        }
    }

    async fn get_all_events(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> HashMap<EventId, UnsignedEvent> {
        let current_sessions = dbtx
            .find_by_prefix(&SessionNoncePrefix)
            .await
            .filter_map(|(session_key, session_nonces)| async move {
                if session_nonces.nonces.is_empty()
                    || !session_nonces
                        .nonces
                        .contains_key(&self.cfg.private.my_peer_id)
                {
                    None
                } else {
                    let unsigned_event = session_nonces.unsigned_event;
                    Some((unsigned_event, session_key.signing_session))
                }
            })
            .collect::<Vec<_>>()
            .await;

        let mut unsigned_events = HashMap::new();
        for (unsigned_event, signing_session) in current_sessions {
            let event_id = unsigned_event.compute_id();
            // No signature share was found for this session for us
            if dbtx
                .get_value(&SignatureShareKey {
                    event_id,
                    signing_session,
                })
                .await
                .is_none()
            {
                unsigned_events.insert(event_id, unsigned_event);
            }
        }

        unsigned_events
    }
}

/// Shares exchanged during DKG including the proof of possession signature.
pub type FrostShare = (BTreeMap<PublicScalar, SecretScalar>, Signature);

/// Iterator the produces `SigningSession`s for all combinations of signers
/// given the threshold and total number of signers.
///
/// The iterator will produce (N choose threshold - 1) number of combinations
/// where the given `PeerId` is always included in the signing sessions.
struct SigningSessionIter {
    combination_iter: Box<dyn Iterator<Item = Vec<PeerId>> + Send + Sync>,
}

impl SigningSessionIter {
    fn new(peer_id: PeerId, consensus: &RoastrConfigConsensus) -> SigningSessionIter {
        let all_peers = consensus.all_peers.clone();
        let threshold = consensus.frost_key.threshold();

        // ROAST requires starting signing sessions for all combinations of peers where
        // `peer_id` exists in the signing session.
        let combination_iter = all_peers
            .into_iter()
            .combinations(threshold)
            .filter(move |peers| peers.contains(&peer_id));

        SigningSessionIter {
            combination_iter: Box::new(combination_iter),
        }
    }
}

impl Iterator for SigningSessionIter {
    type Item = SigningSession;

    fn next(&mut self) -> Option<Self::Item> {
        self.combination_iter.next().map(SigningSession::new)
    }
}
