use fedimintd::fedimintd::Fedimintd;
use schnorr_fun::frost;
use sha2::Sha256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new()?
        .with_default_modules()
        .with_module(nostr_server::NostrInit {
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        })
        .with_extra_module_inits_params(
            3,
            nostr_common::KIND,
            nostr_common::config::NostrGenParams::default(),
        )
        .run()
        .await
}
