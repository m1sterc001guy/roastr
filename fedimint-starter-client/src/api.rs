use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::EventuallyConsistent;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};

// FIXME: we should figure this out at runtime
pub const HARDCODED_INSTANCE_ID_STARTER: ModuleInstanceId = 3;

#[apply(async_trait_maybe_send!)]
pub trait StarterFederationApi {
    async fn ping(&self) -> FederationResult<String>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> StarterFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn ping(&self) -> FederationResult<String> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            format!("module_{HARDCODED_INSTANCE_ID_STARTER}_ping"),
            ApiRequestErased::default(),
        )
        .await
    }
}
