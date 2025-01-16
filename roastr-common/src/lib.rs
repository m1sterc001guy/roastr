use core::hash::Hash;
use std::fmt::{self, Display};
use std::io::ErrorKind;
use std::num::NonZeroU32;
use std::ops::Deref;
use std::str::FromStr;

use config::RoastrClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, PeerId};
use nostr_sdk::{EventId as NdkEventId, JsonUtil, UnsignedEvent as NdkUnsignedEvent};
use rand::rngs::OsRng;
use schnorr_fun::frost::EncodedFrostKey;
use schnorr_fun::fun::marker::{NonZero, Public, Secret, Zero};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use serde::{Deserialize, Serialize};
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256VarCore};
use thiserror::Error;

pub mod config;
pub mod endpoint_constants;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("roastr");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

// Type definition for FROST
pub type Frost = schnorr_fun::frost::Frost<
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum RoastrConsensusItem {
    Nonce(Box<NonceKeyPair>),
    SigningSession((UnsignedEvent, SigningSession)),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct RoastrInput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct RoastrOutput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct RoastrOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum RoastrInputError {
    InvalidOperation(String),
}

impl fmt::Display for RoastrInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoastrInputError::InvalidOperation(msg) => write!(f, "InvalidOperation: {msg}"),
        }
    }
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum RoastrOutputError {
    InvalidOperation(String),
}

impl fmt::Display for RoastrOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoastrOutputError::InvalidOperation(msg) => write!(f, "InvalidOperation: {msg}"),
        }
    }
}

/// Contains the types defined above
pub struct RoastrModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    RoastrModuleTypes,
    RoastrClientConfig,
    RoastrInput,
    RoastrOutput,
    RoastrOutcome,
    RoastrConsensusItem,
    RoastrInputError,
    RoastrOutputError
);

#[derive(Debug)]
pub struct RoastrCommonInit;

impl CommonModuleInit for RoastrCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = RoastrClientConfig;

    fn decoder() -> Decoder {
        RoastrModuleTypes::decoder()
    }
}

impl fmt::Display for RoastrInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoastrInput")
    }
}

impl fmt::Display for RoastrOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoastrOutput")
    }
}

impl fmt::Display for RoastrOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoastrOutcome")
    }
}

impl fmt::Display for RoastrConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoastrConsensusItem::Nonce(keypair) => {
                write!(f, "Nonce: {keypair:?}")
            }
            RoastrConsensusItem::SigningSession((unsigned_event, session)) => {
                write!(f, "UnsignedEvent: {unsigned_event:?} Session: {session:?}")
            }
        }
    }
}

/// Helper function for converting between `PeerId` and scalars
/// that FROST expects
pub fn peer_id_to_scalar(peer_id: &PeerId) -> schnorr_fun::fun::Scalar<Public> {
    let id = (peer_id.to_usize() + 1) as u32;
    schnorr_fun::fun::Scalar::from_non_zero_u32(
        NonZeroU32::new(id).expect("NonZeroU32 returned None"),
    )
    .public()
}

#[derive(Debug, Clone, Serialize, PartialEq, Deserialize)]
pub struct NonceKeyPair(schnorr_fun::musig::NonceKeyPair);

impl NonceKeyPair {
    pub fn new(nonce: schnorr_fun::musig::NonceKeyPair) -> NonceKeyPair {
        NonceKeyPair(nonce)
    }
}

impl Hash for NonceKeyPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes)
            .expect("NonceKeyPair should be encodable");
        state.write(&bytes);
    }
}

impl Eq for NonceKeyPair {}

impl Encodable for NonceKeyPair {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        let len = writer.write(&bytes)?;
        Ok(len)
    }
}

impl Decodable for NonceKeyPair {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut bytes = [0; 64];
        r.read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode NonceKeyPair"))?;
        match schnorr_fun::musig::NonceKeyPair::from_bytes(bytes) {
            Some(keypair) => Ok(NonceKeyPair(keypair)),
            None => Err(DecodeError::from_str(
                "Failed to create NonceKeyPair from bytes",
            )),
        }
    }
}

impl Deref for NonceKeyPair {
    type Target = schnorr_fun::musig::NonceKeyPair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UnsignedEvent(NdkUnsignedEvent);

impl UnsignedEvent {
    pub fn new(unsigned_event: NdkUnsignedEvent) -> UnsignedEvent {
        UnsignedEvent(unsigned_event)
    }

    pub fn compute_id(&self) -> EventId {
        EventId::new(NdkEventId::new(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags.as_slice(),
            &self.content,
        ))
    }

    pub fn add_roast_signature(
        self,
        sig: nostr_sdk::secp256k1::schnorr::Signature,
    ) -> Result<nostr_sdk::Event, nostr_sdk::event::unsigned::Error> {
        self.0.add_signature(sig)
    }
}

impl Encodable for UnsignedEvent {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.as_json().as_bytes().consensus_encode(writer)
    }
}

impl Decodable for UnsignedEvent {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode(r, modules)?;
        let json = String::from_utf8(bytes)
            .map_err(|_| DecodeError::from_str("Failed to convert bytes to json"))?;
        let event = nostr_sdk::UnsignedEvent::from_json(json)
            .map_err(|_| DecodeError::from_str("Failed to convert json to UnsignedEvent"))?;
        Ok(UnsignedEvent(event))
    }
}

impl Deref for UnsignedEvent {
    type Target = NdkUnsignedEvent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct EventId(NdkEventId);

impl EventId {
    pub fn new(event_id: NdkEventId) -> EventId {
        EventId(event_id)
    }
}

impl Encodable for EventId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for EventId {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 32];
        r.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        let event_id = NdkEventId::from_slice(&bytes).map_err(DecodeError::from_err)?;
        Ok(EventId(event_id))
    }
}

impl Deref for EventId {
    type Target = NdkEventId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for EventId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EventId::new(NdkEventId::from_str(s)?))
    }
}

#[derive(Debug, Clone)]
pub struct Point(schnorr_fun::fun::Point);

impl Point {
    pub fn new(point: schnorr_fun::fun::Point) -> Point {
        Point(point)
    }
}

impl Encodable for Point {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        let len = writer.write(&bytes)?;
        Ok(len)
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

impl Deref for Point {
    type Target = schnorr_fun::fun::Point;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Hash)]
pub struct PublicScalar(schnorr_fun::fun::Scalar<Public, NonZero>);

impl PublicScalar {
    pub fn new(scalar: schnorr_fun::fun::Scalar<Public, NonZero>) -> PublicScalar {
        PublicScalar(scalar)
    }
}

impl Encodable for PublicScalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        let len = writer.write(&bytes)?;
        Ok(len)
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
                    .expect("Found zero public scalar"),
            )),
            None => Err(DecodeError::from_str("Failed to decode Scalar")),
        }
    }
}

impl Deref for PublicScalar {
    type Target = schnorr_fun::fun::Scalar<Public, NonZero>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretScalar(schnorr_fun::fun::Scalar<Secret, Zero>);

impl SecretScalar {
    pub fn new(scalar: schnorr_fun::fun::Scalar<Secret, Zero>) -> SecretScalar {
        SecretScalar(scalar)
    }
}

impl Encodable for SecretScalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        let len = writer.write(&bytes)?;
        Ok(len)
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

impl Deref for SecretScalar {
    type Target = schnorr_fun::fun::Scalar<Secret, Zero>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Signature(schnorr_fun::Signature);

impl Signature {
    pub fn new(sig: schnorr_fun::Signature) -> Signature {
        Signature(sig)
    }
}

impl Encodable for Signature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        let len = writer.write(&bytes)?;
        Ok(len)
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

impl Deref for Signature {
    type Target = schnorr_fun::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct RoastrKey(EncodedFrostKey);

impl RoastrKey {
    pub fn new(key: EncodedFrostKey) -> RoastrKey {
        RoastrKey(key)
    }

    pub fn public_key(&self) -> nostr_sdk::PublicKey {
        let pubkey = self.0.into_frost_key().public_key().to_xonly_bytes();
        nostr_sdk::PublicKey::from_slice(&pubkey).expect("Failed to create xonly public key")
    }
}

impl Encodable for RoastrKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let frost_key_bytes = bincode2::serialize(&self.0).map_err(|_| {
            std::io::Error::new(ErrorKind::Other, "Error serializing FrostKey".to_string())
        })?;
        let len = writer.write(frost_key_bytes.as_slice())?;
        Ok(len)
    }
}

impl Decodable for RoastrKey {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // We assume the frost key will be 107 bytes
        let mut frost_key_bytes: [u8; 107] = [0; 107];
        r.read_exact(&mut frost_key_bytes)
            .map_err(DecodeError::from_err)?;
        let frost_key = bincode2::deserialize(&frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Failed to deserialize FrostKey"))?;
        Ok(RoastrKey(frost_key))
    }
}

impl Hash for RoastrKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let frost_key_bytes = bincode2::serialize(&self.0)
            .map_err(|_| {
                std::io::Error::new(ErrorKind::Other, "Error serializing FrostKey".to_string())
            })
            .expect("Could not serialize EncodedFrostKey into bytes");
        state.write(&frost_key_bytes);
    }
}

impl Deref for RoastrKey {
    type Target = EncodedFrostKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignatureShare {
    pub share: PublicScalar,
    pub nonce: NonceKeyPair,
    pub unsigned_event: UnsignedEvent,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SigningSession {
    sorted_peers: Vec<PeerId>,
}

impl Display for SigningSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let peers_str = self
            .sorted_peers
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<String>>()
            .join(",");
        f.write_str(peers_str.as_str())
    }
}

impl Iterator for SigningSession {
    type Item = PeerId;

    fn next(&mut self) -> Option<Self::Item> {
        self.sorted_peers.pop()
    }
}

impl SigningSession {
    pub fn new(mut peers: Vec<PeerId>) -> SigningSession {
        peers.sort();
        SigningSession {
            sorted_peers: peers,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUnsignedEventRequest {
    pub signing_session: SigningSession,
    pub event_id: EventId,
}
