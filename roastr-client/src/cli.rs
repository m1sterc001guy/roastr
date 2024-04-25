use std::{ffi, iter};

use clap::Parser;
use fedimint_client::ClientHandleArc;
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
        description: Option<String>,
    },
}

pub(crate) async fn handle_cli_command(
    roastr: &RoastrClientModule,
    args: &[ffi::OsString],
    client: ClientHandleArc,
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
        Commands::CreateFederationAnnouncement { description } => {
            let event_id = create_federation_announcement(client, roastr, description).await?;
            json!({
                "event_id": event_id,
            })
        }
    };

    Ok(res)
}
