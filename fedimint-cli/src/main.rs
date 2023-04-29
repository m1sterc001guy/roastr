use fedimint_cli::FedimintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new()?
        .with_default_modules()
        .run()
        // .with_module(fedimint_client_server::DummyClientGen)
        .await;
    Ok(())
}
