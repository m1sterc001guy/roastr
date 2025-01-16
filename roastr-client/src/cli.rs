use std::{ffi, iter};

use clap::Parser;
use roastr_common::EventId;
use serde::Serialize;
use serde_json::json;

use crate::{create_federation_announcement, RoastrClientModule};

#[derive(Parser, Serialize)]
enum Commands {
    CreateNote {
        #[arg(long)]
        text: String,
    },
    SignNote {
        #[arg(long)]
        event_id: EventId,
    },
    GetEventSessions {
        #[arg(long)]
        event_id: EventId,
    },
    BroadcastNote {
        #[arg(long)]
        event_id: EventId,
    },
    GetNumNonces,
    CreateFederationAnnouncement {
        #[arg(long)]
        description: Option<String>,

        #[arg(long)]
        network: bitcoin::Network,
    },
    GetSignableNotes,
    VerifyNoteSignature {
        #[arg(long)]
        event_id: EventId,
    },
}

pub(crate) async fn handle_cli_command(
    roastr: &RoastrClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let command =
        Commands::parse_from(iter::once(&ffi::OsString::from("roastr")).chain(args.iter()));

    let res = match command {
        Commands::CreateNote { text } => {
            let event_id = roastr.create_note(text).await?;
            json!({
                "event_id": event_id,
            })
        }
        Commands::SignNote { event_id } => {
            roastr.sign_note(event_id).await?;
            serde_json::Value::Bool(true)
        }
        Commands::GetEventSessions { event_id } => {
            let signing_sessions = roastr.get_signing_sessions(event_id).await?;
            json!(signing_sessions)
        }
        Commands::BroadcastNote { event_id } => {
            let broadcast_response = roastr.broadcast_note(event_id).await?;
            json!(broadcast_response)
        }
        Commands::GetNumNonces => {
            let num_nonces = roastr.get_num_nonces().await?;
            json!(num_nonces)
        }
        Commands::CreateFederationAnnouncement {
            description,
            network,
        } => {
            let event_id = create_federation_announcement(roastr, description, network).await?;
            json!({
                "event_id": event_id,
            })
        }
        Commands::GetSignableNotes => {
            let signable_notes = roastr.get_all_notes().await?;
            json!(signable_notes)
        }
        Commands::VerifyNoteSignature { event_id } => {
            let signed_note = roastr.create_signed_note(event_id).await?;
            let signature = signed_note.sig;
            let msg = nostr_sdk::secp256k1::Message::from_digest(event_id.to_bytes());
            let ctx = nostr_sdk::secp256k1::Secp256k1::new();
            let pubkey = roastr.frost_key.public_key();
            ctx.verify_schnorr(&signature, &msg, &pubkey)?;
            serde_json::Value::Bool(true)
        }
    };

    Ok(res)
}
