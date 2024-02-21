use std::collections::{BTreeMap, BTreeSet};
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
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, CoreConsensusVersion, IDynCommonModuleInit, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{push_db_pair_items, OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use itertools::Itertools;
use rand::rngs::OsRng;
use roastr_common::config::{
    RoastrClientConfig, RoastrConfig, RoastrConfigConsensus, RoastrConfigLocal,
    RoastrConfigPrivate, RoastrGenParams,
};
use roastr_common::endpoint_constants::{
    CREATE_NOTE_ENDPOINT, GET_EVENT_SESSIONS_ENDPOINT, SIGN_NOTE_ENDPOINT,
};
use roastr_common::{
    peer_id_to_scalar, EventId, Frost, NonceKeyPair, Point, PublicScalar, RoastrCommonInit,
    RoastrConsensusItem, RoastrInput, RoastrInputError, RoastrKey, RoastrModuleTypes,
    RoastrOutcome, RoastrOutput, RoastrOutputError, SecretScalar, Signature, SignatureShare,
    SigningSession, UnsignedEvent, CONSENSUS_VERSION, KIND,
};
use schnorr_fun::fun::poly;
use schnorr_fun::Message;
use strum::IntoEnumIterator;
use tracing::info;

use crate::db::{DbKeyPrefix, NoncePrefix, SessionNonces, SignatureShareKey, SignatureSharePrefix};

mod db;

/// Generates the module
#[derive(Clone)]
pub struct RoastrInit {
    pub frost: Frost,
}

#[async_trait]
impl ModuleInit for RoastrInit {
    type Common = RoastrCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Dumps all database items for debugging
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
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Roastr::new(args.cfg().to_typed()?, self.frost.clone()).into())
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        _peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        /*
        peers
            .iter()
            .map(|&peer| {
                let config = RoastrConfig {
                    local: RoastrConfigLocal {},
                    private: RoastrConfigPrivate,
                    consensus: RoastrConfigConsensus {
                        threshold: params.consensus.threshold,
                    },
                };
                (peer, config.to_erased())
            })
            .collect()
        */
        todo!()
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
            .map(|point| Point::new(point.clone()))
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
                        .map(|point| point.deref().clone())
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
                        shares_from_peer
                            .0
                            .get(&PublicScalar::new(my_index))
                            .expect("Didnt find our share")
                            .deref()
                            .clone(),
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

        tracing::info!(
            "MyIndex: {my_index} MySecretShare: {my_secret_share} FrostKey: {frost_key:?}"
        );

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

        // If the difference between `num_nonces` and `nonces` is positive, we need to
        // produce some nonces as consensus items to pre-prepare the list of
        // nonces.
        let num_new_nonces = num_nonces as i32 - nonces.len() as i32;
        for _ in 0..num_new_nonces {
            let nonce = NonceKeyPair::new(schnorr_fun::musig::NonceKeyPair::random(
                &mut rand::rngs::OsRng,
            ));
            consensus_items.push(RoastrConsensusItem::Nonce(nonce));
        }

        // Query for signing sessions that have no nonces selected
        let signing_sessions = dbtx
            .find_by_prefix(&SessionNoncePrefix)
            .await
            .collect::<Vec<_>>()
            .await;
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
                // Check if we already have enough nonces for this peer
                let nonces = dbtx
                    .find_by_prefix(&NoncePeerPrefix { peer_id })
                    .await
                    .collect::<Vec<_>>()
                    .await;

                let num_nonces = self.cfg.consensus.num_nonces;
                if nonces.len() < num_nonces as usize {
                    tracing::info!(
                        "Processing Nonce consensus item. PeerId: {peer_id} Nonce: {nonce:?}"
                    );
                    dbtx.insert_new_entry(&NonceKey { peer_id, nonce }, &())
                        .await;
                }
            }
            RoastrConsensusItem::SigningSession((unsigned_event, signing_session)) => {
                // Deterministically dequeue the nonces from the pre-preared list and assign
                // them to this signing session
                let nonces = self.dequeue_nonces(dbtx, &signing_session).await?;
                let event_id = EventId::new(unsigned_event.id);
                tracing::info!(
                    "Inserting nonces for peers: {signing_session} Heard from PeerId: {peer_id}"
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
                let my_peer_id = self.cfg.private.my_peer_id;
                if peer_id == my_peer_id {
                    let sig_share = self.create_sig_share(unsigned_event.clone(), nonces).await;
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
                    //check_auth(context)?;

                    let mut dbtx = context.dbtx();
                    let event_id = EventId::new(unsigned_event.id);
                    let my_peer_id = module.cfg.private.my_peer_id;
                    let mut sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    while let Some(signing_session) = sign_session_iter.next() {
                        info!("Creating signing session: {signing_session} for note {unsigned_event:?}");
                        dbtx.insert_new_entry(&SessionNonceKey { event_id, signing_session }, &SessionNonces::new(unsigned_event.clone())).await;
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                SIGN_NOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Roastr, context, event_id: EventId| -> () {
                    //check_auth(context)?;

                    let mut dbtx = context.dbtx();

                    let my_peer_id = module.cfg.private.my_peer_id;
                    let mut sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    while let Some(sign_session) = sign_session_iter.next() {
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
        let signature = dbtx
            .find_by_prefix(&SignatureShareEventPrefix { event_id })
            .await
            .next()
            .await;
        if let Some(signature) = signature {
            Some(signature.1.unsigned_event)
        } else {
            None
        }
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
                tracing::info!(
                    "Signature Share already exists for {event_id:?} for {signing_session}. Nothing to do."
                );
                return;
            }

            tracing::info!("Creating signature share for {event_id:?} for {signing_session}");
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
                tracing::info!("Starting new sign session for {event_id:?} for {signing_session}");
                dbtx.insert_new_entry(
                    &SessionNonceKey {
                        event_id,
                        signing_session,
                    },
                    &SessionNonces::new(unsigned_event.clone()),
                )
                .await;
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
        let mut peers_iter = signing_session.clone().into_iter();
        while let Some(peer_id) = peers_iter.next() {
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
        let message_raw = Message::raw(unsigned_event.id.as_bytes());

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
        let my_secret_share = self.cfg.private.my_secret_share.clone();
        let my_index = &self.cfg.private.my_peer_id;
        let my_nonce = nonces
            .get(&my_index)
            .expect("This peer did not contribute a nonce. This should never happen, we should only create signature shares for sessions we are apart of.")
            .clone();
        let my_sig_share = self.frost.sign(
            &xonly_frost_key,
            &session,
            peer_id_to_scalar(&my_index),
            &my_secret_share,
            my_nonce.deref().clone(),
        );

        let signature_share = SignatureShare {
            share: PublicScalar::new(my_sig_share.non_zero().expect("Signature share was zero")),
            nonce: my_nonce,
            unsigned_event,
        };

        signature_share
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
        let combination_iter = all_peers
            .into_iter()
            .combinations(threshold)
            .into_iter()
            .filter(move |peers| peers.contains(&peer_id));

        SigningSessionIter {
            combination_iter: Box::new(combination_iter),
        }
    }
}

impl Iterator for SigningSessionIter {
    type Item = SigningSession;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(combination) = self.combination_iter.next() {
            Some(SigningSession::new(combination))
        } else {
            None
        }
    }
}
