use std::env;
use std::fmt::Write;
use std::path::Path;

use devimint::util::ProcessManager;
use devimint::{cmd, dev_fed, vars, DevFed};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::write_overwrite_async;
use tokio::fs;
use tracing::{debug, info};

#[tokio::test(flavor = "multi_thread")]
async fn starter_test() -> anyhow::Result<()> {
    let (process_mgr, _) = setup().await?;

    let DevFed { fed, .. } = dev_fed(&process_mgr).await?;

    let init_bal = fed.client_balance().await?;
    assert_eq!(init_bal, 0);

    cmd!(
        "fedimint-cli",
        "module",
        "--module=3",
        "print-money",
        "1500"
    )
    .run()
    .await?;

    let final_bal = fed.client_balance().await?;
    assert_eq!(final_bal, 1500);

    Ok(())
}

async fn setup() -> anyhow::Result<(ProcessManager, TaskGroup)> {
    let globals = vars::Global::new(
        Path::new(&env::var("FM_TEST_DIR")?),
        env::var("FM_FED_SIZE")?.parse::<usize>()?,
    )
    .await?;
    let log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(globals.FM_LOGS_DIR.join("devimint.log"))
        .await?
        .into_std()
        .await;

    fedimint_logging::TracingSetup::default()
        .with_file(Some(log_file))
        .init()?;

    let mut env_string = String::new();
    for (var, value) in globals.vars() {
        debug!(var, value, "Env variable set");
        writeln!(env_string, r#"export {var}="{value}""#)?; // hope that value doesn't contain a "
        std::env::set_var(var, value);
    }
    write_overwrite_async(globals.FM_TEST_DIR.join("env"), env_string).await?;
    info!("Test setup in {:?}", globals.FM_DATA_DIR);
    let process_mgr = ProcessManager::new(globals);
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();
    Ok((process_mgr, task_group))
}
