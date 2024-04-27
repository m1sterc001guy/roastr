# ROASTR

ROASTR is a Fedimint module for collaboratively signing Nostr events. ROAST is a robust threshold signing algorithm for producing Schnorr signatures. Since Nostr uses Schnorr signatures for signing broadcasted notes, ROAST can be used to build a federated module for signing Nostr events. Inspired by [Nick Farrow's Frostr](https://github.com/nickfarrow/frostr).

## How does it work?
During federation setup, the guardians work together to compute a join public key (i.e the federation's "npub") that the federation can sign under. Each guardian holds a private key share for the joint public key, but no single guardian knows the joint private key. In order to sign a Nostr event, each guardian must request their server to produce a signature share using the guardian's private key share, the nostr event, and the nonces that were previously agreed on for the signing session. Once a `t/n` signature shares have been created, the final Schnorr signature can be created by combining all of the signature shares together. The signature is then attached to the Nostr event and broadcasted to the Nostr network.

## Why ROAST and not FROST?
ROAST is simply a wrapper on top of FROST that makes it more robust. Because FROST is a two-round signing algorithm (nonce round + signing round), it is possible to commit to a set of nonces from a particular set of guardians in the first round, then a malicious guardian could without their signature in the second round, which would stall the signing process and result in failing to produce a signature. ROAST solves this by spawning many FROST sessions in parallel. Because many FROST sessions are running in parallel, this guarantees that if there are an honest quorum of guardians willing to sign the Nostr event, a valid signature will be created. These parallel FROST sessions improve the robustness of FROST, but at the expense of efficiency, since some signing sessions may fail to produce a signature or will be redundant work. ROAST is better suited for adversarial scenarios where some members of the federation might be malicious or unreliable. More on ROAST can be found [here](https://medium.com/blockstream/roast-robust-asynchronous-schnorr-threshold-signatures-ddda55a07d1b) and [here](https://eprint.iacr.org/2022/550.pdf).

## Running ROASTR

To run ROASTR, you'll need to have Nix installed.

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Then, fork and clone this repo

```bash
git clone https://github.com/m1sterc001guy/roastr.git
```

and run the following command to start the nix developer environment

```bash
nix develop
```

Then, you can run fedimint with ROASTR installed with

```bash
just mprocs
```

## Using ROASTR

First, create a note to be signed. This can be done by any guardian, but the correct password must be supplied since it is an admin command.

```bash
fedimint-cli --our-id=0 --password=pass module roastr create-note --text ROASTR
```

This will produce an event id. Copy the event id.

At any point during this process, we can check the state of the signing sessions and which signature shares have been produced:

```bash
fedimint-cli module roastr get-event-sessions --event_id <event_id>
```

Below is an example output. We can see that after creating the note with guardian 0, 3 signing sessions have been created. We have one signing session that commits to guardians 0,1,2, one signing session that commits to guardians 0,1,3, and one signing session that commits to guardians 0,2,3. Each signing session has a single (but unique!) signature share. As we sign with more guardians, more signature shares will be added to these signing sessions.

```
{
  "0,1,2": {
    "0": {
      "share": "1d7d6aa61124451dc4464cec02a42427c5faf824e7b3a44017e74403a69fe88d",
      "nonce": "5ba9fe2d2a77af89e324f66cf47d0cd2623e7b106fc78969800963f2e8d3cd2339538ff44abe9b78de13d9e1f895687b4679adab3ad27a26090e0ce7244b8e77",
      "unsigned_event": {
        "pubkey": "896e24b879ebed0a9b47cc88439ec9e893ede5aab1f28f3337ab7d772ef38f3c",
        "created_at": 1714186840,
        "kind": 1,
        "tags": [],
        "content": "ROASTR"
      }
    }
  },
  "0,1,3": {
    "0": {
      "share": "8822824d2d7d2b9f7f385f7755955bbb7acd163092821c8fc13e8600a243a55c",
      "nonce": "69189f85c7fdbe17cccc7de86f74364de3255334c7212068994fde589c9e86179b22b89a6360f125ca7ee1aad2b0dc6a99d71d1697881ee822a786c982dc6ba8",
      "unsigned_event": {
        "pubkey": "896e24b879ebed0a9b47cc88439ec9e893ede5aab1f28f3337ab7d772ef38f3c",
        "created_at": 1714186840,
        "kind": 1,
        "tags": [],
        "content": "ROASTR"
      }
    }
  },
  "0,2,3": {
    "0": {
      "share": "9ea1a4260972ae62faef1c5fabebd9d9f572412ec0be6e5d2a00ac337eccda71",
      "nonce": "6dcb220a463bc6dbf4a7a8d1f28a90cb98694b6afb724636d28fa706c8422b356aadbc3d25113878f59819f668c550dce77bf6c7c5f2f8724ef38e7bee06b911",
      "unsigned_event": {
        "pubkey": "896e24b879ebed0a9b47cc88439ec9e893ede5aab1f28f3337ab7d772ef38f3c",
        "created_at": 1714186840,
        "kind": 1,
        "tags": [],
        "content": "ROASTR"
      }
    }
  }
}
```

To sign with another guardian, use another admin command:

```bash
fedimint-cli --our-id=1 --password=pass module roastr sign-note --event-id <event_id>
```

In our test federation, since we have 4 guardians, we need 3 to sign. So sign with a 3rd guardian:

```bash
fedimint-cli --our-id=2 --password=pass module roastr sign-note --event-id <event_id>
```

At this point, guardians 0,1,2 have all produced signature shares and we should be able to create a combined Schnorr signature!

```bash
fedimint-cli module roastr broadcast-note --event-id <event_id>
```

This will combined the signature shares into a Schnorr signature, attach the signature to the Nostr note, and broadcast the note to Nostr using [Blastr](https://github.com/MutinyWallet/blastr).

An example output is provided below:

```
{
  "federation_npub": "npub139hzfwrea0ks4x68ejyy88kfazf7med2k8eg7veh4d7hwthn3u7q4td06y",
  "event_id": "note1chlxq2lu50j73pkgulzah3jekukz833zelun8xt9aapwuevnlt0qgt7l00"
}
```

## Creating Federation Announcements
Nostr has [NIP-87](https://github.com/nostr-protocol/nips/pull/1110) for broadcasting federation announcements via Nostr. These federation announcements allow users to discover Mints over Nostr and wallets (e.g MutinyWallet) can leverage the web of trust graph of Nostr to recommend e-cash mints to users based on friend's recommendations. Now, with ROASTR, these federation announcements can be signed by the mint itself!

```bash
fedimint-cli --our-id=0 --password=pass module roastr create-federation-announcement
```

The procedure for signing the note and broadcasting it to Nostr is the same as above.


## Help
Reach out to [m1sterc001guy](https://primal.net/p/npub1zswjq57t99f444z6485xtn0vfyjjfu8vqpnyj6uckuyem2446evqnxgc6x) on Nostr for any questions.