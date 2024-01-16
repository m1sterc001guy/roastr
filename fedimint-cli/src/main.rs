use fedimint_cli::FedimintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new("0.1")?
        .with_default_modules()
        .with_module(nostr_client::NostrClientInit)
        .run()
        .await;
    Ok(())
}
