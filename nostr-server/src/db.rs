use std::collections::BTreeMap;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use nostr_common::{NonceKeyPair, PublicScalar, UnsignedEvent};
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
    pub unsigned_event: UnsignedEvent,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SigningSessionKeyPrefix;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SigningSessionPeerPrefix {
    pub peers: Vec<PeerId>,
}

impl_db_record!(key = SigningSessionKey, value = BTreeMap<PeerId, NonceKeyPair>, db_prefix = DbKeyPrefix::SigningSession);

impl_db_lookup!(
    key = SigningSessionKey,
    query_prefix = SigningSessionKeyPrefix,
    query_prefix = SigningSessionPeerPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignatureShareKey {
    pub unsigned_event: UnsignedEvent,
    pub peers: Vec<PeerId>,
}

impl_db_record!(
    key = SignatureShareKey,
    value = PublicScalar,
    db_prefix = DbKeyPrefix::SignatureShare
);
