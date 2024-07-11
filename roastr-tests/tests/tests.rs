use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{AdminCreds, Client, ClientHandle, ClientHandleArc};
use fedimint_core::config::ClientConfig;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::ApiAuth;
use fedimint_core::task::sleep_in_test;
use fedimint_core::PeerId;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_logging::LOG_TEST;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::WalletClientInit;
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_server::WalletInit;
use roastr_client::{create_federation_announcement, RoastrClientInit, RoastrClientModule};
use roastr_common::config::RoastrGenParams;
use roastr_common::EventId;
use roastr_server::RoastrInit;
use schnorr_fun::frost;
use sha2::Sha256;
use tracing::info;

/// Creates the test fixtures by attaching the Dummy, Roastr, and Wallet
/// modules.
fn fixtures() -> Fixtures {
    let mut fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    fixtures = fixtures.with_module(
        RoastrClientInit,
        RoastrInit {
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        },
        RoastrGenParams::default(),
    );
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());
    let wallet_client = WalletClientInit::new(fixtures.bitcoin_client());
    fixtures.with_module(wallet_client, WalletInit, wallet_params)
}

/// Creates a new admin client given the `ClientConfig`. This is a workaround
/// and should not be necessary once `FederationTest::new_admin_client` is
/// available.
async fn new_admin_client(
    client_config: ClientConfig,
    peer_id: PeerId,
    auth: ApiAuth,
) -> ClientHandleArc {
    info!(target: LOG_TEST, "Setting new client with config");
    let mut client_builder = Client::builder(MemDatabase::new().into());
    let mut client_module_registry = ClientModuleInitRegistry::new();
    client_module_registry.attach(DummyClientInit);
    client_module_registry.attach(WalletClientInit::default());
    client_module_registry.attach(RoastrClientInit);
    client_builder.with_module_inits(client_module_registry);
    client_builder.with_primary_module(0);
    client_builder.set_admin_creds(AdminCreds { peer_id, auth });
    let client_secret = Client::load_or_generate_client_secret(client_builder.db_no_decoders())
        .await
        .unwrap();
    client_builder
        .join(
            PlainRootSecretStrategy::to_root_secret(&client_secret),
            client_config,
        )
        .await
        .map(Arc::new)
        .expect("Failed to build client")
}

/// Creates a admin client for every peer in the federation.
async fn create_admin_clients(
    fed: &FederationTest,
    num_peers: u16,
    password: String,
) -> anyhow::Result<BTreeMap<PeerId, Arc<ClientHandle>>> {
    let client_config =
        fedimint_server::config::ClientConfig::download_from_invite_code(&fed.invite_code())
            .await?;
    let mut admin_clients = BTreeMap::new();
    for peer_id in 0..num_peers {
        let admin_client = new_admin_client(
            client_config.clone(),
            peer_id.into(),
            ApiAuth(password.clone()),
        )
        .await;
        admin_clients.insert(peer_id.into(), admin_client);
    }

    Ok(admin_clients)
}

/// For the given `curr_peer_id`, this function will wait until that peer has
/// processed a nonce consensus item from every other peer in the federation,
/// except if instructed to ignore peers in `peers_to_ignore`.
async fn wait_for_nonces(
    curr_peer_id: &PeerId,
    admin_client: &Arc<ClientHandle>,
    peers_to_ignore: HashSet<PeerId>,
) -> anyhow::Result<()> {
    let roastr = admin_client.get_first_module::<RoastrClientModule>();
    // Wait until this admin has heard of at least one nonce from the peer (except
    // for peers in `peers_to_ignore`)
    loop {
        let num_nonces = roastr.get_num_nonces().await?;
        let num_nonces = num_nonces
            .into_iter()
            .find(|(_, num_nonces)| *num_nonces < 1);
        match num_nonces {
            Some((peer_id, _)) => {
                if peers_to_ignore.contains(&peer_id) {
                    break;
                }

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

/// Queries all peers to check if a given signing sessions exist and verifies if
/// each signing session has the expected number of signature shares.
async fn contains_expected_signing_sessions(
    user_client: &Arc<ClientHandle>,
    event_id: EventId,
    expected_sessions: Vec<(&str, usize)>,
) -> anyhow::Result<()> {
    let roastr = user_client.get_first_module::<RoastrClientModule>();
    let event_sessions = roastr.get_signing_sessions(event_id).await?;
    for (expected_session, expected_shares) in expected_sessions.iter() {
        match event_sessions.get(*expected_session) {
            Some(peer_nonces) => {
                assert_eq!(
                    peer_nonces.len(),
                    *expected_shares,
                    "Incorrect number of signature shares for session"
                );
            }
            None => {
                return Err(anyhow::anyhow!("Does not contain expected signing session"));
            }
        }
    }

    Ok(())
}

/// Waits for the given signing session to exist in consensus and verifies that
/// each signing session has the expected number of signature shares.
async fn wait_for_signing_sessions(
    user_client: &Arc<ClientHandle>,
    event_id: EventId,
    expected_sessions: Vec<(&str, usize)>,
) -> anyhow::Result<()> {
    loop {
        match contains_expected_signing_sessions(user_client, event_id, expected_sessions.clone())
            .await
        {
            Ok(_) => return Ok(()),
            Err(_) => {
                sleep_in_test(
                    format!("EventID: {event_id:?} Waiting for expected signing sessions {expected_sessions:?}"),
                    Duration::from_secs(1),
                )
                .await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn can_sign_with_degraded() -> anyhow::Result<()> {
    let fixtures = fixtures();
    // `new_fed` always creates a 4 member federation with one guardian offline
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;

    let admin_clients = create_admin_clients(&fed, 3, "pass".to_string()).await?;

    // Wait for all clients to have nonces so that all ROAST signing sessions are
    // created.
    for (peer_id, admin_client) in admin_clients.iter() {
        wait_for_nonces(peer_id, admin_client, [3.into()].into_iter().collect()).await?;
    }

    // Create the note to be broadcasted to nostr
    let guardian0 = admin_clients
        .get(&0.into())
        .expect("Admin clients has guardian 0");
    let roastr0 = guardian0.get_first_module::<RoastrClientModule>();
    let event_id = roastr0.create_note("ROASTR".to_string()).await?;

    wait_for_signing_sessions(&user_client, event_id, [("0,1,2", 1)].to_vec()).await?;

    // Sign with guardian 1
    let guardian1 = admin_clients
        .get(&1.into())
        .expect("Admin clients has guardian 1");
    let roastr1 = guardian1.get_first_module::<RoastrClientModule>();
    roastr1.sign_note(event_id).await?;
    wait_for_signing_sessions(&user_client, event_id, [("0,1,2", 2)].to_vec()).await?;

    // Sign with guardian 2
    let guardian2 = admin_clients
        .get(&2.into())
        .expect("Admin clients has guardian 2");
    let roastr2 = guardian2.get_first_module::<RoastrClientModule>();
    roastr2.sign_note(event_id).await?;
    wait_for_signing_sessions(&user_client, event_id, [("0,1,2", 3)].to_vec()).await?;

    // Verify the signature on the signed note
    let roastr = user_client.get_first_module::<RoastrClientModule>();
    let signed_note = roastr.create_signed_note(event_id).await?;
    let signature = signed_note.signature();
    let event_id = signed_note.id;
    let msg = nostr_sdk::secp256k1::Message::from_digest(event_id.to_bytes());
    let ctx = nostr_sdk::secp256k1::Secp256k1::new();
    let pubkey = roastr.frost_key.public_key();
    ctx.verify_schnorr(&signature, &msg, &pubkey)?;
    info!(
        ?signature,
        ?pubkey,
        ?event_id,
        "Successfully verified signature"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn all_guardians_sign_note() -> anyhow::Result<()> {
    let num_peers = 4;
    let fixtures = fixtures();
    let fed = fixtures.new_fed_with_peers(num_peers, 0).await;
    let user_client = fed.new_client().await;

    let admin_clients = create_admin_clients(&fed, num_peers, "pass".to_string()).await?;

    // Wait for all clients to have nonces so that all ROAST signing sessions are
    // created.
    for (peer_id, admin_client) in admin_clients.iter() {
        wait_for_nonces(peer_id, admin_client, [].into_iter().collect()).await?;
    }

    // Create the note to be broadcasted to nostr
    let guardian0 = admin_clients
        .get(&0.into())
        .expect("Admin clients has guardian 0");
    let roastr0 = guardian0.get_first_module::<RoastrClientModule>();
    let event_id = roastr0.create_note("ROASTR".to_string()).await?;

    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 1), ("0,1,3", 1), ("0,2,3", 1)].to_vec(),
    )
    .await?;

    // Sign with guardian 1
    let guardian1 = admin_clients
        .get(&1.into())
        .expect("Admin clients has guardian 1");
    let roastr1 = guardian1.get_first_module::<RoastrClientModule>();
    roastr1.sign_note(event_id).await?;
    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 2), ("0,1,3", 2), ("0,2,3", 1), ("1,2,3", 1)].to_vec(),
    )
    .await?;

    // Sign with guardian 3
    let guardian3 = admin_clients
        .get(&3.into())
        .expect("Admin clients has guardian 3");
    let roastr3 = guardian3.get_first_module::<RoastrClientModule>();
    roastr3.sign_note(event_id).await?;
    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 2), ("0,1,3", 3), ("0,2,3", 2), ("1,2,3", 2)].to_vec(),
    )
    .await?;

    // Verify the signature on the signed note
    let roastr = user_client.get_first_module::<RoastrClientModule>();
    let signed_note = roastr.create_signed_note(event_id).await?;
    let signature = signed_note.signature();
    let event_id = signed_note.id;
    let msg = nostr_sdk::secp256k1::Message::from_digest(event_id.to_bytes());
    let ctx = nostr_sdk::secp256k1::Secp256k1::new();
    let pubkey = roastr.frost_key.public_key();
    ctx.verify_schnorr(&signature, &msg, &pubkey)?;
    info!(
        ?signature,
        ?pubkey,
        ?event_id,
        "Successfully verified signature"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn all_guardians_sign_federation_announcement() -> anyhow::Result<()> {
    let num_peers = 4;
    let fixtures = fixtures();
    let fed = fixtures.new_fed_with_peers(num_peers, 0).await;
    let user_client = fed.new_client().await;

    let admin_clients = create_admin_clients(&fed, num_peers, "pass".to_string()).await?;

    // Wait for all clients to have nonces so that all ROAST signing sessions are
    // created.
    for (peer_id, admin_client) in admin_clients.iter() {
        wait_for_nonces(peer_id, admin_client, [].into_iter().collect()).await?;
    }

    // Create the note to be broadcasted to nostr
    let guardian0 = admin_clients
        .get(&0.into())
        .expect("Admin clients has guardian 0");
    let event_id = create_federation_announcement(
        guardian0.clone(),
        Some("Testing Roastr Federation Announcements".to_string()),
    )
    .await?;

    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 1), ("0,1,3", 1), ("0,2,3", 1)].to_vec(),
    )
    .await?;

    // Sign with guardian 1
    let guardian1 = admin_clients
        .get(&1.into())
        .expect("Admin clients has guardian 1");
    let roastr1 = guardian1.get_first_module::<RoastrClientModule>();
    roastr1.sign_note(event_id).await?;
    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 2), ("0,1,3", 2), ("0,2,3", 1), ("1,2,3", 1)].to_vec(),
    )
    .await?;

    // Sign with guardian 3
    let guardian3 = admin_clients
        .get(&3.into())
        .expect("Admin clients has guardian 3");
    let roastr3 = guardian3.get_first_module::<RoastrClientModule>();
    roastr3.sign_note(event_id).await?;
    wait_for_signing_sessions(
        &user_client,
        event_id,
        [("0,1,2", 2), ("0,1,3", 3), ("0,2,3", 2), ("1,2,3", 2)].to_vec(),
    )
    .await?;

    // Verify the signature on the signed note
    let roastr = user_client.get_first_module::<RoastrClientModule>();
    let signed_note = roastr.create_signed_note(event_id).await?;
    let signature = signed_note.signature();
    let event_id = signed_note.id;
    let msg = nostr_sdk::secp256k1::Message::from_digest(event_id.to_bytes());
    let ctx = nostr_sdk::secp256k1::Secp256k1::new();
    let pubkey = roastr.frost_key.public_key();
    ctx.verify_schnorr(&signature, &msg, &pubkey)?;
    info!(
        ?signature,
        ?pubkey,
        ?event_id,
        "Successfully verified signature"
    );

    Ok(())
}
