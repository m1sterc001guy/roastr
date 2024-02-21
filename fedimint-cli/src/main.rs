use fedimint_cli::FedimintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: Fix this version hash
    FedimintCli::new("e1efadacfa61f0e5f898a217bdc48ea781702000")?
        .with_default_modules()
        .with_module(roastr_client::RoastrClientInit)
        .run()
        .await;
    Ok(())
}
