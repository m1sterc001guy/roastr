use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::task::sleep_in_test;
use fedimint_core::PeerId;
use roastr_common::{EventId, SignatureShare, UnsignedEvent};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fed = dev_fed.fed().await?;
        let client0 = fed.new_joined_client("guardian0").await?;
        let client1 = fed.new_joined_client("guardian1").await?;
        let client2 = fed.new_joined_client("guardian2").await?;
        let client3 = fed.new_joined_client("guardian3").await?;
        wait_for_nonces(&client0, PeerId::from(0)).await?;
        wait_for_nonces(&client1, PeerId::from(1)).await?;
        wait_for_nonces(&client2, PeerId::from(2)).await?;
        wait_for_nonces(&client3, PeerId::from(3)).await?;

        info!("roastr guardian 0 creating text note...");
        let event_id = create_note(&client0, PeerId::from(0), "ROASTR").await?;
        wait_for_signing_session(&client0, &event_id, "0,1,2", 1).await?;
        wait_for_signing_session(&client0, &event_id, "0,1,3", 1).await?;
        wait_for_signing_session(&client0, &event_id, "0,2,3", 1).await?;

        info!(?event_id, "roastr guardian 1 signing text note...");
        peer_can_sign_note(&client1, PeerId::from(1), &event_id).await?;
        sign_note(&client1, PeerId::from(1), &event_id).await?;
        wait_for_signing_session(&client1, &event_id, "0,1,2", 2).await?;
        wait_for_signing_session(&client1, &event_id, "0,1,3", 2).await?;
        wait_for_signing_session(&client1, &event_id, "1,2,3", 1).await?;
        wait_for_signing_session(&client1, &event_id, "0,2,3", 1).await?;

        info!(?event_id, "roastr guardian 2 signing text note...");
        peer_can_sign_note(&client2, PeerId::from(2), &event_id).await?;
        sign_note(&client2, PeerId::from(2), &event_id).await?;
        wait_for_signing_session(&client2, &event_id, "0,1,2", 3).await?;
        wait_for_signing_session(&client2, &event_id, "0,1,3", 2).await?;
        wait_for_signing_session(&client2, &event_id, "1,2,3", 2).await?;
        wait_for_signing_session(&client2, &event_id, "0,2,3", 2).await?;

        info!(?event_id, "verifying text note signature...");
        verify_note_signature(&client0, &event_id).await?;

        info!("roastr guardian 3 creating federation announcement...");
        let announcement_id = create_federation_announcement(&client3, PeerId::from(3)).await?;
        wait_for_signing_session(&client3, &announcement_id, "0,1,3", 1).await?;
        wait_for_signing_session(&client3, &announcement_id, "1,2,3", 1).await?;
        wait_for_signing_session(&client3, &announcement_id, "0,2,3", 1).await?;

        info!(?announcement_id, "roastr guardian 0 signing text note...");
        peer_can_sign_note(&client0, PeerId::from(0), &announcement_id).await?;
        sign_note(&client0, PeerId::from(0), &announcement_id).await?;
        wait_for_signing_session(&client0, &announcement_id, "0,1,2", 1).await?;
        wait_for_signing_session(&client0, &announcement_id, "0,1,3", 2).await?;
        wait_for_signing_session(&client0, &announcement_id, "1,2,3", 1).await?;
        wait_for_signing_session(&client0, &announcement_id, "0,2,3", 2).await?;

        info!(?announcement_id, "roastr guardian 1 signing text note...");
        peer_can_sign_note(&client1, PeerId::from(1), &announcement_id).await?;
        sign_note(&client1, PeerId::from(1), &announcement_id).await?;
        wait_for_signing_session(&client1, &announcement_id, "0,1,2", 2).await?;
        wait_for_signing_session(&client1, &announcement_id, "0,1,3", 3).await?;
        wait_for_signing_session(&client1, &announcement_id, "1,2,3", 2).await?;
        wait_for_signing_session(&client1, &announcement_id, "0,2,3", 2).await?;

        info!(
            ?announcement_id,
            "verifying federation announcement note signature..."
        );
        verify_note_signature(&client3, &announcement_id).await?;

        info!("Successfully completed roastr test");
        Ok(())
    })
    .await
}

async fn create_federation_announcement(
    client: &Client,
    peer_id: PeerId,
) -> anyhow::Result<EventId> {
    Ok(serde_json::from_value(
        cmd!(
            client,
            "--our-id",
            peer_id.to_string(),
            "--password",
            "pass",
            "module",
            "roastr",
            "create-federation-announcement",
            "--description",
            "RegtestFedimintDescription",
            "--network",
            "regtest"
        )
        .out_json()
        .await?["event_id"]
            .clone(),
    )?)
}

async fn verify_note_signature(client: &Client, event_id: &EventId) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "roastr",
        "verify-note-signature",
        "--event-id",
        event_id.to_string()
    )
    .run()
    .await?)
}

async fn wait_for_nonces(client: &Client, curr_peer_id: PeerId) -> anyhow::Result<()> {
    loop {
        let nonces_val = cmd!(
            client,
            "--our-id",
            curr_peer_id.to_string(),
            "--password",
            "pass",
            "module",
            "roastr",
            "get-num-nonces"
        )
        .out_json()
        .await?;
        let nonce_map: BTreeMap<PeerId, usize> = serde_json::from_value(nonces_val)?;
        let num_nonces = nonce_map
            .into_iter()
            .find(|(_, num_nonces)| *num_nonces < 1);
        match num_nonces {
            Some((peer_id, _)) => {
                sleep_in_test(
                    format!("Peer {curr_peer_id} waiting for a nonce from {peer_id}"),
                    Duration::from_secs(1),
                )
                .await;
            }
            None => {
                break;
            }
        }
    }

    Ok(())
}

async fn peer_can_sign_note(
    client: &Client,
    peer_id: PeerId,
    event_id: &EventId,
) -> anyhow::Result<()> {
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
    let notes: HashMap<EventId, UnsignedEvent> = serde_json::from_value(notes_val)?;
    assert!(notes.contains_key(event_id));
    Ok(())
}

async fn sign_note(client: &Client, peer_id: PeerId, event_id: &EventId) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "--our-id",
        peer_id.to_string(),
        "--password",
        "pass",
        "module",
        "roastr",
        "sign-note",
        "--event-id",
        event_id.to_string()
    )
    .run()
    .await?)
}

async fn create_note(client: &Client, peer_id: PeerId, text: &str) -> anyhow::Result<EventId> {
    Ok(serde_json::from_value::<EventId>(
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
    event_id: &EventId,
    session: &str,
    num_sig_shares: usize,
) -> anyhow::Result<()> {
    loop {
        match contains_signing_session(client, event_id, session, num_sig_shares).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                let event_id_str = event_id.to_string();
                sleep_in_test(
                    format!(
                        "EventID: {event_id_str} Waiting for expected signing session {session}"
                    ),
                    Duration::from_secs(1),
                )
                .await;
            }
        }
    }
}

async fn contains_signing_session(
    client: &Client,
    event_id: &EventId,
    session: &str,
    num_sig_shares: usize,
) -> anyhow::Result<()> {
    let val = cmd!(
        client,
        "module",
        "roastr",
        "get-event-sessions",
        "--event-id",
        event_id.to_string(),
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
