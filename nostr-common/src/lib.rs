use core::hash::Hash;
use std::fmt::{self, Display};
use std::num::NonZeroU32;
use std::ops::Deref;

use config::NostrClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, PeerId};
use nostr_sdk::{EventId, UnsignedEvent as NdkUnsignedEvent};
use rand::rngs::OsRng;
use schnorr_fun::frost::Frost;
use schnorr_fun::fun::marker::{NonZero, Public, Secret, Zero};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use serde::{Deserialize, Serialize};
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256VarCore};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("nostr");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

// Type definition for FROST
pub type NostrFrost = Frost<
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
pub enum NostrConsensusItem {
    Nonce(NonceKeyPair),
    SigningSession((UnsignedEvent, SigningSession)),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct NostrInput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct NostrOutput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct NostrOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum NostrInputError {
    InvalidOperation(String),
}

impl fmt::Display for NostrInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NostrInputError::InvalidOperation(msg) => write!(f, "InvalidOperation: {msg}"),
        }
    }
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum NostrOutputError {
    InvalidOperation(String),
}

impl fmt::Display for NostrOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NostrOutputError::InvalidOperation(msg) => write!(f, "InvalidOperation: {msg}"),
        }
    }
}

/// Contains the types defined above
pub struct NostrModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    NostrModuleTypes,
    NostrClientConfig,
    NostrInput,
    NostrOutput,
    NostrOutcome,
    NostrConsensusItem,
    NostrInputError,
    NostrOutputError
);

#[derive(Debug)]
pub struct NostrCommonInit;

impl CommonModuleInit for NostrCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = NostrClientConfig;

    fn decoder() -> Decoder {
        NostrModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for NostrInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrInput")
    }
}

impl fmt::Display for NostrOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrOutput")
    }
}

impl fmt::Display for NostrOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrOutputOutcome")
    }
}

impl fmt::Display for NostrConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrConsensusItem")
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
        writer.write(&bytes)?;
        Ok(bytes.len())
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
pub struct UnsignedEvent(pub NdkUnsignedEvent);

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

/// Wrapper type for nostr's event id that. Needed for implementing
/// Encodable/Decodable
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct NostrEventId(pub EventId);

impl Encodable for NostrEventId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for NostrEventId {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode(r, modules)?;
        let event_id =
            EventId::from_slice(bytes.as_slice()).map_err(|e| DecodeError::from_err(e))?;
        Ok(NostrEventId(event_id))
    }
}

#[derive(Debug, Clone)]
pub struct Point(pub schnorr_fun::fun::Point);

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

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Hash)]
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
                    .expect("Found zero public scalar"),
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
pub struct Signature(pub schnorr_fun::Signature);

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

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
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
