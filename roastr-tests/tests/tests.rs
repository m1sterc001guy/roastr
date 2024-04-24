use std::collections::BTreeMap;
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
use roastr_client::{RoastrClientInit, RoastrClientModule};
use roastr_common::config::RoastrGenParams;
use roastr_server::RoastrInit;
use schnorr_fun::frost;
use sha2::Sha256;
use tracing::info;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    fixtures.with_module(
        RoastrClientInit,
        RoastrInit {
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        },
        RoastrGenParams::default(),
    )
}

async fn new_admin_client(
    client_config: ClientConfig,
    peer_id: PeerId,
    auth: ApiAuth,
) -> ClientHandleArc {
    info!(target: LOG_TEST, "Setting new client with config");
    let mut client_builder = Client::builder(MemDatabase::new().into());
    let mut client_module_registry = ClientModuleInitRegistry::new();
    client_module_registry.attach(DummyClientInit);
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

async fn wait_for_nonces(
    curr_peer_id: &PeerId,
    admin_client: &Arc<ClientHandle>,
) -> anyhow::Result<()> {
    let roastr = admin_client.get_first_module::<RoastrClientModule>();
    // Wait until this admin has heard of at least one nonce from each peer
    loop {
        let num_nonces = roastr.get_num_nonces().await?;
        let num_nonces = num_nonces
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

#[tokio::test(flavor = "multi_thread")]
async fn can_sign_nostr_text_note() -> anyhow::Result<()> {
    let num_peers = 4;
    let fixtures = fixtures();
    let fed = fixtures.new_fed_with_peers(num_peers, 0).await;
    let user_client = fed.new_client().await;
    let roastr = user_client.get_first_module::<RoastrClientModule>();

    let admin_clients = create_admin_clients(&fed, num_peers, "pass".to_string()).await?;

    // TODO: This can be done in parallel
    for (peer_id, admin_client) in admin_clients.iter() {
        wait_for_nonces(peer_id, admin_client).await?;
    }

    //let guardian0 = admin_clients.get(&0.into()).expect("Admin clients has
    // guardian 0"); let roastr1 =
    // guardian0.get_first_module::<RoastrClientModule>(); let event_id =
    // roastr1.create_note("ROASTR".to_string()).await?; tracing::info!("Event:
    // {event_id:?}");

    // TODO: Remove this
    //fedimint_core::task::sleep_in_test(
    //    "Sleeping to wait for sessions to be created",
    //    Duration::from_secs(120),
    //)
    //.await;
    //tracing::info!("DONE SLEEPING");

    // Verify the correct sessions were created
    //let event_sessions = roastr.get_signing_sessions(event_id).await?;
    //tracing::info!("EventSessions: {event_sessions:?}");
    //assert_eq!(event_sessions.len(), 3);
    //let expected_sessions = ["0,1,2", "0,1,3", "0,2,3"];
    //for session in expected_sessions {
    //    assert!(event_sessions.contains_key(session), "Event Sessions did not
    // contain {session}")
    //}

    Ok(())
}
