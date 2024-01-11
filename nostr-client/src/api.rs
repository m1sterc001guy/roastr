use fedimint_core::api::IModuleFederationApi;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

#[apply(async_trait_maybe_send!)]
pub trait NostrFederationApi {}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> NostrFederationApi for T where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static
{
}
