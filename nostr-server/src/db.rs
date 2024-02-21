use std::collections::BTreeMap;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use nostr_common::{NonceKeyPair, NostrEventId, SignatureShare, UnsignedEvent};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Nonce = 0x01,
    SigningSession = 0x02,
    SignatureShare = 0x03,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKey {
    pub peer_id: PeerId,
    pub nonce: NonceKeyPair,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKeyPrefix {
    pub peer_id: PeerId,
}

impl_db_record!(key = NonceKey, value = (), db_prefix = DbKeyPrefix::Nonce);

impl_db_lookup!(key = NonceKey, query_prefix = NonceKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SigningSessionKey {
    pub peers: Vec<PeerId>,
    pub event_id: NostrEventId,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SigningSession {
    pub nonces: BTreeMap<PeerId, NonceKeyPair>,
    pub unsigned_event: UnsignedEvent,
}

impl SigningSession {
    pub fn new(unsigned_event: UnsignedEvent) -> SigningSession {
        SigningSession {
            nonces: BTreeMap::new(),
            unsigned_event,
        }
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SigningSessionKeyPrefix;

impl_db_record!(
    key = SigningSessionKey,
    value = SigningSession,
    db_prefix = DbKeyPrefix::SigningSession
);

impl_db_lookup!(
    key = SigningSessionKey,
    query_prefix = SigningSessionKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignatureShareKey {
    pub event_id: NostrEventId,
    pub peers: Vec<PeerId>,
}

impl_db_record!(
    key = SignatureShareKey,
    value = SignatureShare,
    db_prefix = DbKeyPrefix::SignatureShare
);
