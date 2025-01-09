use fedimint_core::fedimint_build_code_version_env;
use fedimintd::Fedimintd;
use schnorr_fun::frost;
use sha2::Sha256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new(fedimint_build_code_version_env!(), None)?
        .with_default_modules()?
        .with_module_kind(roastr_server::RoastrInit {
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        })
        .with_module_instance(
            roastr_common::KIND,
            roastr_common::config::RoastrGenParams::default(),
        )
        .run()
        .await
}
