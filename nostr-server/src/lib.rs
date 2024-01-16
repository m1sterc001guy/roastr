use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, MigrationMap};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CoreConsensusVersion, IDynCommonModuleInit, InputMeta, ModuleConsensusVersion,
    ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions,
    TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use nostr_common::config::{
    NostrClientConfig, NostrConfig, NostrConfigConsensus, NostrConfigLocal, NostrConfigPrivate,
    NostrGenParams,
};
use nostr_common::{
    NostrCommonInit, NostrConsensusItem, NostrInput, NostrInputError, NostrModuleTypes,
    NostrOutput, NostrOutputError, NostrOutputOutcome, CONSENSUS_VERSION, KIND,
};
use rand::rngs::OsRng;
use schnorr_fun::frost::{self, Frost};
use schnorr_fun::fun::marker::{NonZero, Public, Secret, Zero};
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
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

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

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
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
            local: NostrConfigLocal {},
            private: NostrConfigPrivate {
                my_secret_share,
                my_peer_id: peers.our_id,
            },
            consensus: NostrConfigConsensus { threshold },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<NostrClientConfig> {
        let _config = NostrConfigConsensus::from_erased(config)?;
        Ok(NostrClientConfig {})
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

fn peer_id_to_scalar(peer_id: &PeerId) -> schnorr_fun::fun::Scalar<Public> {
    let id = (peer_id.to_usize() + 1) as u32;
    schnorr_fun::fun::Scalar::from_non_zero_u32(
        NonZeroU32::new(id).expect("NonZeroU32 returned None"),
    )
    .public()
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
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<NostrConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: NostrConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("The nostr module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b NostrInput,
    ) -> Result<InputMeta, NostrInputError> {
        todo!()
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a NostrOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, NostrOutputError> {
        todo!()
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<NostrOutputOutcome> {
        todo!()
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
        todo!()
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}

impl Nostr {
    /// Create new module instance
    pub fn new(cfg: NostrConfig, frost: NostrFrost) -> Nostr {
        Nostr { cfg, frost }
    }
}

#[derive(Debug, Clone)]
struct Point(pub schnorr_fun::fun::Point);

impl Encodable for Point {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for Point {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut bytes = [0; 33];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode Point"))?;
        match schnorr_fun::fun::Point::from_bytes(bytes) {
            Some(p) => Ok(Point(p)),
            None => Err(DecodeError::from_str("Failed to decode Point")),
        }
    }
}

pub type FrostShare = (BTreeMap<PublicScalar, SecretScalar>, Signature);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicScalar(pub schnorr_fun::fun::Scalar<Public, NonZero>);

impl Encodable for PublicScalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for PublicScalar {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 32];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode Scalar"))?;
        match schnorr_fun::fun::Scalar::<Secret, Zero>::from_bytes(bytes) {
            Some(scalar) => Ok(PublicScalar(
                scalar
                    .public()
                    .non_zero()
                    .expect("Found PublicScalar that was Zero"),
            )),
            None => Err(DecodeError::from_str("Failed to decode Scalar")),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretScalar(pub schnorr_fun::fun::Scalar<Secret, Zero>);

impl Encodable for SecretScalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for SecretScalar {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 32];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode Scalar"))?;
        match schnorr_fun::fun::Scalar::<Secret, Zero>::from_bytes(bytes) {
            Some(scalar) => Ok(SecretScalar(scalar)),
            None => Err(DecodeError::from_str("Failed to decode Scalar")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature(schnorr_fun::Signature);

impl Encodable for Signature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for Signature {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 64];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode Signature"))?;
        match schnorr_fun::Signature::from_bytes(bytes) {
            Some(sig) => Ok(Signature(sig)),
            None => Err(DecodeError::from_str("Failed to decode Signature")),
        }
    }
}
