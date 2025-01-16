#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        tracing::info!("roastr running devimint test");
        Ok(())
    })
    .await
}
