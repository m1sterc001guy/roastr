use std::collections::BTreeMap;

use async_trait::async_trait;
use db::{NonceKey, NonceKeyPrefix, SignatureShareKey};
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
use fedimint_core::{Amount, OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use nostr_common::config::{
    NostrClientConfig, NostrConfig, NostrConfigConsensus, NostrConfigLocal, NostrConfigPrivate,
    NostrGenParams, NostrNPub,
};
use nostr_common::{
    peer_id_to_scalar, NonceKeyPair, NostrCommonInit, NostrConsensusItem, NostrInput,
    NostrInputError, NostrModuleTypes, NostrOutputError, NostrSignatureShareOutcome,
    NostrSignatureShareRequest, Point, PublicScalar, SecretScalar, Signature, UnsignedEvent,
    CONSENSUS_VERSION, KIND,
};
use rand::rngs::OsRng;
use schnorr_fun::frost::{self, Frost};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::Message;
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256VarCore};

mod db;

type NostrFrost = Frost<
    CoreWrapper<
        CtVariableCoreWrapper<
            Sha256VarCore,
            UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
            OidSha256,
        >,
    >,
    Synthetic<
        CoreWrapper<
            CtVariableCoreWrapper<
                Sha256VarCore,
                UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                OidSha256,
            >,
        >,
        GlobalRng<OsRng>,
    >,
>;

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
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a NostrSignatureShareRequest,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, NostrOutputError> {
        /*
        // Verify that our peer id is include in the set of signers
        if output.signing_peers.contains(&self.cfg.private.my_peer_id) {
            let frost_key = self.cfg.consensus.frost_key.clone();
            let xonly_frost_key = frost_key.into_xonly_key();
            let message_raw = Message::raw(output.unsigned_event.0.id.as_bytes());

            let mut nonces = BTreeMap::new();
            for peer_id in &output.signing_peers {
                // Always use the first available nonce for the peer
                let (nonce_key, _) = match dbtx
                    .find_by_prefix(&NonceKeyPrefix { peer_id: *peer_id })
                    .await
                    .next()
                    .await
                {
                    Some(nonce) => nonce,
                    None => {
                        return Err(NostrOutputError::NotEnoughNonces(
                            "Not enough nonces for peer: {peer_id}".to_string(),
                        ))
                    }
                };

                let scalar_id = peer_id_to_scalar(&nonce_key.peer_id);
                nonces.insert(scalar_id, nonce_key.nonce.0.clone());

                // remove the nonce from the database
                dbtx.remove_entry(&nonce_key).await;
            }

            let session_nonces = nonces
                .clone()
                .into_iter()
                .map(|(key, nonce_pair)| (key, nonce_pair.public()))
                .collect::<BTreeMap<_, _>>();
            let session =
                self.frost
                    .start_sign_session(&xonly_frost_key, session_nonces, message_raw);
            let my_secret_share = self.cfg.private.my_secret_share.clone();
            let my_index = peer_id_to_scalar(&self.cfg.private.my_peer_id);
            let my_nonce = nonces
                .get(&my_index)
                .expect("We did not contribute a nonce")
                .clone();
            let my_sig_share = self.frost.sign(
                &xonly_frost_key,
                &session,
                my_index,
                &my_secret_share,
                my_nonce,
            );

            dbtx.insert_new_entry(
                &SignatureShareKey { out_point },
                &NostrSignatureShareOutcome {
                    signature_share: PublicScalar(
                        my_sig_share
                            .non_zero()
                            .expect("My signature share was zero"),
                    ),
                },
            )
            .await;
        }
        */

        Ok(TransactionItemAmount {
            amount: Amount::ZERO,
            fee: Amount::ZERO,
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<NostrSignatureShareOutcome> {
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
        vec![api_endpoint! {
            "sign_event",
            ApiVersion::new(0, 0),
            async |_module: &Nostr, context, unsigned_event: UnsignedEvent| -> () {
                //check_auth(context)?;
                tracing::info!("Received sign_message request. Message: {unsigned_event:?}");
                //let mut dbtx = context.dbtx();
                //dbtx.insert_new_entry(&MessageNonceRequest, &unsigned_event).await;
                Ok(())
            }
        }]
    }
}

impl Nostr {
    /// Create new module instance
    pub fn new(cfg: NostrConfig, frost: NostrFrost) -> Nostr {
        Nostr { cfg, frost }
    }
}

pub type FrostShare = (BTreeMap<PublicScalar, SecretScalar>, Signature);
