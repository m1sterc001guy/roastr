use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use anyhow::anyhow;
use async_trait::async_trait;
use db::{
    NonceKey, NonceKeyPrefix, SessionNonceKey, SignatureShareKeyPrefix, SigningSessionKeyPrefix,
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
use fedimint_core::{OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use itertools::Itertools;
use nostr_common::config::{
    NostrClientConfig, NostrConfig, NostrConfigConsensus, NostrConfigLocal, NostrConfigPrivate,
    NostrFrostKey, NostrGenParams,
};
use nostr_common::{
    peer_id_to_scalar, NonceKeyPair, NostrCommonInit, NostrConsensusItem, NostrEventId, NostrFrost,
    NostrInput, NostrInputError, NostrModuleTypes, NostrOutcome, NostrOutput, NostrOutputError,
    Point, PublicScalar, SecretScalar, Signature, SignatureShare, SigningSession, UnsignedEvent,
    CONSENSUS_VERSION, KIND,
};
use rand::rngs::OsRng;
use schnorr_fun::fun::poly;
use schnorr_fun::Message;

use crate::db::{SessionNonces, SignatureShareKey};

mod db;

/// Generates the module
#[derive(Clone)]
pub struct NostrInit {
    pub frost: NostrFrost,
}

#[async_trait]
impl ModuleInit for NostrInit {
    type Common = NostrCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
    }
}

impl std::fmt::Debug for NostrInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrInit").finish()
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for NostrInit {
    type Params = NostrGenParams;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Nostr::new(args.cfg().to_typed()?, self.frost.clone()).into())
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
                let config = NostrConfig {
                    local: NostrConfigLocal {},
                    private: NostrConfigPrivate,
                    consensus: NostrConfigConsensus {
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
        let my_secret_poly = poly::scalar::generate(threshold as usize, &mut OsRng);
        let my_public_poly = poly::scalar::to_point_poly(&my_secret_poly)
            .iter()
            .map(|point| Point(point.clone()))
            .collect::<Vec<_>>();

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
                    poly.into_iter().map(|point| point.0).collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let my_index = peer_id_to_scalar(&peers.our_id);
        let my_polys = BTreeMap::from_iter([(my_index, &my_secret_poly)]);
        let keygen = self
            .frost
            .new_keygen(public_polynomials, &my_polys)
            .expect("Something went wrong with what was provided by the other parties");
        let keygen_id = self.frost.keygen_id(&keygen);
        let pop_message = Message::raw(&keygen_id);
        let (shares_i_generated, pop) =
            self.frost
                .create_shares_and_pop(&keygen, &my_secret_poly, pop_message);

        let shares_i_generated_converted = shares_i_generated
            .into_iter()
            .map(|(public, secret)| (PublicScalar(public), SecretScalar(secret)))
            .collect::<BTreeMap<_, _>>();

        let shares_and_pop: BTreeMap<PeerId, FrostShare> = peers
            .exchange_with_peers::<FrostShare>(
                "nostr_shares".to_string(),
                (shares_i_generated_converted, Signature(pop)),
                KIND,
                self.decoder(),
            )
            .await?;

        let my_shares = shares_and_pop
            .iter()
            .map(|(peer, shares_from_peer)| {
                let index = peer_id_to_scalar(peer);
                (
                    index,
                    (
                        shares_from_peer
                            .0
                            .get(&PublicScalar(my_index))
                            .expect("Didnt find our share")
                            .0
                            .clone(),
                        shares_from_peer.1 .0.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let (my_secret_share, frost_key) = self
            .frost
            .finish_keygen(keygen.clone(), my_index, my_shares, pop_message)
            .expect("Finish keygen failed");

        tracing::info!(
            "MyIndex: {my_index} MySecretShare: {my_secret_share} FrostKey: {frost_key:?}"
        );

        let all_peers = BTreeSet::from_iter(peers.peer_ids().iter().cloned());

        Ok(NostrConfig {
            local: NostrConfigLocal,
            private: NostrConfigPrivate {
                my_peer_id: peers.our_id,
                my_secret_share,
            },
            consensus: NostrConfigConsensus {
                num_nonces: params.consensus.num_nonces,
                frost_key: NostrFrostKey(frost_key.into()),
                all_peers,
            },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<NostrClientConfig> {
        let config = NostrConfigConsensus::from_erased(config)?;
        Ok(NostrClientConfig {
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

pub struct Nostr {
    cfg: NostrConfig,
    frost: NostrFrost,
}

impl std::fmt::Debug for Nostr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nostr").field("cfg", &self.cfg).finish()
    }
}

#[async_trait]
impl ServerModule for Nostr {
    type Common = NostrModuleTypes;
    type Init = NostrInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<NostrConsensusItem> {
        let num_nonces = self.cfg.consensus.num_nonces;

        let mut consensus_items = Vec::new();

        // Query the database to see if we have enough nonces
        let my_peer_id = self.cfg.private.my_peer_id;
        let nonces = dbtx
            .find_by_prefix(&NonceKeyPrefix {
                peer_id: my_peer_id,
            })
            .await
            .collect::<Vec<_>>()
            .await;
        let num_new_nonces = num_nonces as i32 - nonces.len() as i32;
        for _ in 0..num_new_nonces {
            let nonce = NonceKeyPair::new(schnorr_fun::musig::NonceKeyPair::random(
                &mut rand::rngs::OsRng,
            ));
            consensus_items.push(NostrConsensusItem::Nonce(nonce));
        }

        // Query for signing sessions that have no nonces selected
        let signing_sessions = dbtx
            .find_by_prefix(&SigningSessionKeyPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        for (session_key, session) in signing_sessions {
            if session.nonces.is_empty() {
                consensus_items.push(NostrConsensusItem::SigningSession((
                    session.unsigned_event,
                    session_key.peers,
                )));
            }
        }

        consensus_items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: NostrConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            NostrConsensusItem::Nonce(nonce) => {
                // Check if we already have enough nonces for this peer
                let nonces = dbtx
                    .find_by_prefix(&NonceKeyPrefix { peer_id })
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
            NostrConsensusItem::SigningSession((unsigned_event, peers)) => {
                let nonces = self.get_nonces(dbtx, &peers).await?;
                let event_id = NostrEventId(unsigned_event.0.id);
                tracing::info!(
                    "Inserting nonces for peers: {peers:?} Heard from PeerId: {peer_id}"
                );
                dbtx.insert_entry(
                    &SessionNonceKey {
                        event_id,
                        peers: peers.clone(),
                    },
                    &SessionNonces {
                        nonces: nonces.clone(),
                        unsigned_event: unsigned_event.clone(),
                    },
                )
                .await;

                let my_peer_id = self.cfg.private.my_peer_id;
                if peer_id == my_peer_id {
                    let sig_share = self.create_sig_share(unsigned_event.clone(), nonces).await;
                    dbtx.insert_new_entry(&SignatureShareKey { event_id, peers }, &sig_share)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b NostrInput,
    ) -> Result<InputMeta, NostrInputError> {
        Err(NostrInputError::InvalidOperation(
            "Nostr module does not process inputs".to_string(),
        ))
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a NostrOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, NostrOutputError> {
        Err(NostrOutputError::InvalidOperation(
            "Nostr module does not process output".to_string(),
        ))
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<NostrOutcome> {
        None
    }

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
                "create_note",
                ApiVersion::new(0, 0),
                async |module: &Nostr, context, unsigned_event: UnsignedEvent| -> () {
                    //check_auth(context)?;

                    let mut dbtx = context.dbtx();
                    let event_id = NostrEventId(unsigned_event.0.id);
                    let my_peer_id = module.cfg.private.my_peer_id;
                    let mut sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    while let Some(sign_session) = sign_session_iter.next() {
                        tracing::info!("Creating sign session: {sign_session} for note {unsigned_event:?}");
                        dbtx.insert_new_entry(&SessionNonceKey { event_id, peers: sign_session }, &SessionNonces::new(unsigned_event.clone())).await;
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                "sign_note",
                ApiVersion::new(0, 0),
                async |module: &Nostr, context, event_id: NostrEventId| -> () {
                    //check_auth(context)?;

                    let mut dbtx = context.dbtx();

                    let my_peer_id = module.cfg.private.my_peer_id;
                    let mut sign_session_iter = SigningSessionIter::new(my_peer_id, &module.cfg.consensus);
                    while let Some(sign_session) = sign_session_iter.next() {
                        module.sign_note(&mut dbtx.to_ref_nc(), sign_session.clone(), event_id).await;
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                "get_sig_shares",
                ApiVersion::new(0, 0),
                async |_module: &Nostr, context, event_id: NostrEventId| -> BTreeMap<String, SignatureShare> {

                    let mut dbtx = context.dbtx();

                    let signatures = dbtx
                        .find_by_prefix(&SignatureShareKeyPrefix { event_id })
                        .await
                        .map(|(key, sig_share)| {
                            (key.peers.to_string(), sig_share)
                        })
                        .collect::<BTreeMap<_, _>>()
                        .await;

                    Ok(signatures)
                }
            },
        ]
    }
}

impl Nostr {
    /// Create new module instance
    pub fn new(cfg: NostrConfig, frost: NostrFrost) -> Nostr {
        Nostr { cfg, frost }
    }

    async fn get_unsigned_event_for_id(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        event_id: NostrEventId,
    ) -> Option<UnsignedEvent> {
        let signature = dbtx
            .find_by_prefix(&SignatureShareKeyPrefix { event_id })
            .await
            .next()
            .await;
        if let Some(signature) = signature {
            Some(signature.1.unsigned_event)
        } else {
            None
        }
    }

    async fn sign_note(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: SigningSession,
        event_id: NostrEventId,
    ) {
        let signing_session = dbtx
            .get_value(&SessionNonceKey {
                peers: peers.clone(),
                event_id,
            })
            .await;
        if let Some(session) = signing_session {
            // Check if a signature share for this session already exists
            if dbtx
                .get_value(&SignatureShareKey {
                    peers: peers.clone(),
                    event_id,
                })
                .await
                .is_some()
            {
                tracing::info!(
                    "Signature Share already exists for {event_id:?} for {peers}. Nothing to do."
                );
            } else {
                tracing::info!("Creating signature share for {event_id:?} for {peers}");
                let sig_share = self
                    .create_sig_share(session.unsigned_event.clone(), session.nonces)
                    .await;

                dbtx.insert_entry(
                    &SignatureShareKey {
                        peers: peers.clone(),
                        event_id,
                    },
                    &sig_share,
                )
                .await;
            }
        } else {
            // No signing session exists, create a new one
            if let Some(unsigned_event) = self.get_unsigned_event_for_id(dbtx, event_id).await {
                tracing::info!("Starting new sign session for {event_id:?} for {peers}");
                dbtx.insert_new_entry(
                    &SessionNonceKey { event_id, peers },
                    &SessionNonces::new(unsigned_event.clone()),
                )
                .await;
            }
        }
    }

    async fn get_nonces(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: &SigningSession,
    ) -> anyhow::Result<BTreeMap<PeerId, NonceKeyPair>> {
        let mut nonces = BTreeMap::new();
        let mut peers_iter = peers.clone().into_iter();
        while let Some(peer_id) = peers_iter.next() {
            // Always use the first available nonce for the peer
            let (nonce_key, _) = match dbtx
                .find_by_prefix(&NonceKeyPrefix { peer_id })
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

    async fn create_sig_share(
        &self,
        unsigned_event: UnsignedEvent,
        nonces: BTreeMap<PeerId, NonceKeyPair>,
    ) -> SignatureShare {
        let frost_key = self.cfg.consensus.frost_key.clone();
        let xonly_frost_key = frost_key.0.into_frost_key().into_xonly_key();
        let message_raw = Message::raw(unsigned_event.0.id.as_bytes());
        let session_nonces = nonces
            .clone()
            .into_iter()
            .map(|(key, nonce_pair)| (peer_id_to_scalar(&key), nonce_pair.public()))
            .collect::<BTreeMap<_, _>>();
        let session = self
            .frost
            .start_sign_session(&xonly_frost_key, session_nonces, message_raw);
        let my_secret_share = self.cfg.private.my_secret_share.clone();
        let my_index = &self.cfg.private.my_peer_id;
        let my_nonce = nonces
            .get(&my_index)
            .expect("We did not contribute a nonce")
            .clone();
        let my_sig_share = self.frost.sign(
            &xonly_frost_key,
            &session,
            peer_id_to_scalar(&my_index),
            &my_secret_share,
            my_nonce.deref().clone(),
        );

        tracing::info!("Creating signature share: {my_sig_share:?}");

        let signature_share = SignatureShare {
            share: PublicScalar(my_sig_share.non_zero().expect("Signature share was zero")),
            nonce: my_nonce,
            unsigned_event,
        };

        signature_share
    }
}

pub type FrostShare = (BTreeMap<PublicScalar, SecretScalar>, Signature);

struct SigningSessionIter {
    combination_iter: Box<dyn Iterator<Item = Vec<PeerId>> + Send + Sync>,
}

impl SigningSessionIter {
    fn new(peer_id: PeerId, consensus: &NostrConfigConsensus) -> SigningSessionIter {
        let all_peers = consensus.all_peers.clone();
        let threshold = consensus.frost_key.0.threshold();
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
