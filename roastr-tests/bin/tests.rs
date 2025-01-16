use std::collections::BTreeMap;
use std::time::Duration;

use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::task::sleep_in_test;
use fedimint_core::PeerId;
use roastr_common::SignatureShare;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        info!("roastr guardian 0 creating note...");

        let client0 = dev_fed.fed().await?.new_joined_client("guardian0").await?;
        let event_id = create_note(&client0, PeerId::from(0), "ROASTR").await?;
        wait_for_signing_session(&client0, &event_id, "0,1,2", 1).await?;
        wait_for_signing_session(&client0, &event_id, "0,1,3", 1).await?;
        wait_for_signing_session(&client0, &event_id, "0,2,3", 1).await?;

        info!("Successfully completed roastr test");
        Ok(())
    })
    .await
}

async fn get_signable_note(client: &Client, peer_id: PeerId) -> anyhow::Result<()> {
    let notes_val = cmd!(
        client,
        "--our-id",
        peer_id.to_string(),
        "--password",
        "pass",
        "module",
        "roastr",
        "get-signable-notes"
    )
    .out_json()
    .await?;
    Ok(())
}

async fn create_note(client: &Client, peer_id: PeerId, text: &str) -> anyhow::Result<String> {
    Ok(serde_json::from_value::<String>(
        cmd!(
            client,
            "--our-id",
            peer_id.to_string(),
            "--password",
            "pass",
            "module",
            "roastr",
            "create-note",
            "--text",
            text,
        )
        .out_json()
        .await?["event_id"]
            .clone(),
    )?)
}

async fn wait_for_signing_session(
    client: &Client,
    event_id: &str,
    session: &str,
    num_sig_shares: usize,
) -> anyhow::Result<()> {
    loop {
        match contains_signing_session(client, event_id, session, num_sig_shares).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                sleep_in_test(
                    format!("EventID: {event_id} Waiting for expected signing session {session}"),
                    Duration::from_secs(1),
                )
                .await;
            }
        }
    }
}

async fn contains_signing_session(
    client: &Client,
    event_id: &str,
    session: &str,
    num_sig_shares: usize,
) -> anyhow::Result<()> {
    let val = cmd!(
        client,
        "module",
        "roastr",
        "get-event-sessions",
        "--event-id",
        event_id,
    )
    .out_json()
    .await?;
    let sessions: BTreeMap<String, BTreeMap<PeerId, SignatureShare>> = serde_json::from_value(val)?;
    if !sessions.contains_key(session) {
        return Err(anyhow::anyhow!("Session not available"));
    }
    let sig_shares = sessions.get(session).expect("Already checked");
    assert_eq!(sig_shares.len(), num_sig_shares);
    Ok(())
}
