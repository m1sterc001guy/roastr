use std::collections::BTreeMap;

use anyhow::anyhow;
use async_trait::async_trait;
use db::{
    NonceKey, NonceKeyPrefix, SigningSessionKey, SigningSessionKeyPrefix, SigningSessionPeerPrefix,
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
use nostr_common::config::{
    NostrClientConfig, NostrConfig, NostrConfigConsensus, NostrConfigLocal, NostrConfigPrivate,
    NostrGenParams, NostrNPub,
};
use nostr_common::{
    peer_id_to_scalar, NonceKeyPair, NostrCommonInit, NostrConsensusItem, NostrFrost, NostrInput,
    NostrInputError, NostrModuleTypes, NostrOutcome, NostrOutput, NostrOutputError, Point,
    PublicScalar, SecretScalar, Signature, UnsignedEvent, CONSENSUS_VERSION, KIND,
};
use nostr_sdk::EventId;
use schnorr_fun::{frost, Message};

use crate::db::SignatureShareKey;

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
        let mut rng = rand::rngs::OsRng;
        let params = self.parse_params(params).unwrap();
        let threshold = params.consensus.threshold;
        let my_secret_poly = frost::generate_scalar_poly(threshold as usize, &mut rng);
        let my_public_poly = frost::to_point_poly(&my_secret_poly)
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

        let keygen = self
            .frost
            .new_keygen(public_polynomials)
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

        let my_index = peer_id_to_scalar(&peers.our_id);

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

        Ok(NostrConfig {
            local: NostrConfigLocal,
            private: NostrConfigPrivate {
                my_peer_id: peers.our_id,
                my_secret_share,
            },
            consensus: NostrConfigConsensus {
                threshold,
                frost_key,
                num_nonces: params.consensus.num_nonces,
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
        let public_key = config.frost_key.public_key().to_xonly_bytes();
        let xonly = nostr_sdk::key::XOnlyPublicKey::from_slice(&public_key)?;
        Ok(NostrClientConfig {
            npub: NostrNPub { npub: xonly },
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
            let nonce = NonceKeyPair(schnorr_fun::musig::NonceKeyPair::random(
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
        for (session, nonces) in signing_sessions {
            if nonces.is_empty() {
                consensus_items.push(NostrConsensusItem::SigningSession((
                    session.unsigned_event,
                    session.peers,
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
                tracing::info!(
                    "Inserting nonces for peers: {peers:?} Heard from PeerId: {peer_id}"
                );
                dbtx.insert_entry(
                    &SigningSessionKey {
                        unsigned_event: unsigned_event.clone(),
                        peers: peers.clone(),
                    },
                    &nonces,
                )
                .await;

                let my_peer_id = self.cfg.private.my_peer_id;
                if peer_id == my_peer_id {
                    let sig_share = self
                        .create_sig_share(unsigned_event.clone(), nonces)
                        .await?;
                    dbtx.insert_new_entry(
                        &SignatureShareKey {
                            unsigned_event,
                            peers,
                        },
                        &sig_share,
                    )
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
                async |_module: &Nostr, context, unsigned_event: UnsignedEvent| -> () {
                    //check_auth(context)?;

                    tracing::info!("Received create_note request. Message: {unsigned_event:?}");
                    let mut dbtx = context.dbtx();

                    // Create note will always start new signing sessions
                    // TODO: iterate through all signing sessions
                    let peers: Vec<PeerId> = vec![0.into(), 1.into(), 2.into()];
                    dbtx.insert_new_entry(&SigningSessionKey { unsigned_event, peers }, &BTreeMap::new()).await;

                    Ok(())
                }
            },
            api_endpoint! {
                "sign_note",
                ApiVersion::new(0, 0),
                async |module: &Nostr, context, note_id: EventId| -> () {
                    //check_auth(context)?;

                    tracing::info!("Received sign_note request. EventId: {note_id}");
                    let mut dbtx = context.dbtx();


                    // TODO: iterate through all signing sessions
                    let my_peer_id = module.cfg.private.my_peer_id;
                    let peers: Vec<PeerId> = vec![0.into(), 1.into(), 2.into()];
                    if let Ok(_) = module.sign_note(&mut dbtx.to_ref_nc(), peers, note_id).await {
                        tracing::info!("Peer: {my_peer_id} successfully signed note");
                    } else {
                        tracing::error!("We have hard coded the signing session, we should start a new signing session");
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                "get_sig_shares",
                ApiVersion::new(0, 0),
                async |module: &Nostr, context, note_id: EventId| -> BTreeMap<String, PublicScalar> {

                    let mut dbtx = context.dbtx();
                    let mut sigs = BTreeMap::new();
                    // TODO: iterate through all signing sessions
                    let my_peer_id = module.cfg.private.my_peer_id;
                    let peers: Vec<PeerId> = vec![0.into(), 1.into(), 2.into()];
                    let peers_str = peers
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<String>>()
                        .join(",");

                    if let Ok(Some(sig_share)) = module.get_sig_share(&mut dbtx.to_ref_nc(), peers.clone(), note_id).await {
                        tracing::info!("Received sign_note request. Returning sig share: {sig_share:?}");
                        sigs.insert(peers_str, sig_share);
                        //return Ok(Some(sig_share));
                        return Ok(sigs);
                    }

                    tracing::info!("Received sign_note request. Returning empty...");
                    Ok(sigs)
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

    async fn get_signing_session(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: Vec<PeerId>,
        note_id: EventId,
    ) -> Option<(SigningSessionKey, BTreeMap<PeerId, NonceKeyPair>)> {
        dbtx.find_by_prefix(&SigningSessionPeerPrefix {
            peers: peers.clone(),
        })
        .await
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter(|(session, _)| session.unsigned_event.0.id == note_id)
        .next()
    }

    async fn get_sig_share(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: Vec<PeerId>,
        note_id: EventId,
    ) -> anyhow::Result<Option<PublicScalar>> {
        let signing_session = self.get_signing_session(dbtx, peers.clone(), note_id).await;
        if let Some(session) = signing_session {
            // Check if a signature share for this session already exists
            if let Some(sig_share) = dbtx
                .get_value(&SignatureShareKey {
                    peers: peers.clone(),
                    unsigned_event: session.0.unsigned_event.clone(),
                })
                .await
            {
                return Ok(Some(sig_share));
            } else {
                return Ok(None);
            }
        }

        Err(anyhow!("Signing session does not exist"))
    }

    async fn sign_note(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: Vec<PeerId>,
        note_id: EventId,
    ) -> anyhow::Result<PublicScalar> {
        let signing_session = self.get_signing_session(dbtx, peers.clone(), note_id).await;
        if let Some(session) = signing_session {
            // Check if a signature share for this session already exists
            if let Some(sig_share) = dbtx
                .get_value(&SignatureShareKey {
                    peers: peers.clone(),
                    unsigned_event: session.0.unsigned_event.clone(),
                })
                .await
            {
                tracing::info!("SIGN-NOTE Signature share already exists, nothing to do");
                return Ok(sig_share);
            } else {
                tracing::info!("SIGN-NOTE Signature share does not exist, creating...");
                let sig_share = self
                    .create_sig_share(session.0.unsigned_event.clone(), session.1)
                    .await?;

                dbtx.insert_entry(
                    &SignatureShareKey {
                        peers: peers.clone(),
                        unsigned_event: session.0.unsigned_event.clone(),
                    },
                    &sig_share,
                )
                .await;

                return Ok(sig_share);
            }
        }

        Err(anyhow!("Signing session does not exist"))
    }

    async fn get_nonces(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peers: &Vec<PeerId>,
    ) -> anyhow::Result<BTreeMap<PeerId, NonceKeyPair>> {
        let mut nonces = BTreeMap::new();
        for peer_id in peers {
            // Always use the first available nonce for the peer
            let (nonce_key, _) = match dbtx
                .find_by_prefix(&NonceKeyPrefix { peer_id: *peer_id })
                .await
                .next()
                .await
            {
                Some(nonce) => nonce,
                None => {
                    return Err(anyhow!("Not enough nonces for peer: {peer_id}"));
                }
            };

            //let scalar_id = peer_id_to_scalar(&nonce_key.peer_id);
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
    ) -> anyhow::Result<PublicScalar> {
        let frost_key = self.cfg.consensus.frost_key.clone();
        let xonly_frost_key = frost_key.into_xonly_key();
        let message_raw = Message::raw(unsigned_event.0.id.as_bytes());
        let session_nonces = nonces
            .clone()
            .into_iter()
            .map(|(key, nonce_pair)| (peer_id_to_scalar(&key), nonce_pair.0.public()))
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
            my_nonce.0,
        );

        tracing::info!("Creating signature share: {my_sig_share:?}");

        Ok(PublicScalar(
            my_sig_share.non_zero().expect("Signature share was zero"),
        ))
    }
}

pub type FrostShare = (BTreeMap<PublicScalar, SecretScalar>, Signature);
