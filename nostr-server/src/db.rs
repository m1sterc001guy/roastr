use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, PeerId};
use nostr_common::{NonceKeyPair, NostrSignatureShareOutcome};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Nonce = 0x01,
    SignatureShare = 0x02,
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

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SignatureShareKey {
    pub out_point: OutPoint,
}

impl_db_record!(
    key = SignatureShareKey,
    value = NostrSignatureShareOutcome,
    db_prefix = DbKeyPrefix::SignatureShare,
);
