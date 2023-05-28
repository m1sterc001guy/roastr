use devimint::{cmd, dev_fed, util::ProcessManager, DevFed};
use fedimint_core::task::TaskGroup;
use fedimint_logging::TracingSetup;

#[tokio::test(flavor = "multi_thread")]
async fn starter_test() -> anyhow::Result<()> {
    TracingSetup::default().init()?;
    let process_mgr = ProcessManager::new();
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();

    #[allow(unused_variables)]
    let DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    } = dev_fed(&task_group, &process_mgr).await?;

    let output = cmd!("fedimint-cli", "module", "--id=starter", "--arg=ping")
        .out_string()
        .await?;

    assert_eq!(output, "\"pong\"");

    Ok(())
}
