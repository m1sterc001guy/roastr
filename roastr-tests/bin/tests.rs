use devimint::cmd;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        info!("roastr guardian 0 creating note...");

        let client0 = dev_fed.fed().await?.new_joined_client("guardian0").await?;
        let event_id = cmd!(
            client0,
            "--our-id",
            "0",
            "--password",
            "pass",
            "module",
            "roastr",
            "create-note",
            "--text",
            "ROASTR"
        )
        .out_json()
        .await?["event_id"]
            .to_string();

        info!(?event_id, "EventID");
        Ok(())
    })
    .await
}
