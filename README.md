# pkee

A fingerprint-unlocked, fuzzy-searching launcher for a KeePass (KDBX) database,
native on Wayland. It replaces day-to-day use of the KeePassXC GUI: press a key,
type a few letters, copy, done.

- **No master password.** The database's only key is a 32-byte KeePass key file.
  pkee keeps it wrapped once per device in *slots*, each sealed with a FIDO2
  `hmac-secret` from that device's passkey authenticator, e.g.
  [linux-passkey](https://github.com/koxu1996/linux-passkey) (Secure Enclave or
  TPM, approved with a fingerprint).
- **Fuzzy search + frecency.** [nucleo](https://github.com/helix-editor/nucleo)
  matching (fzf syntax) over title, username, URL host, group and tags, ranked
  up by how often and how recently you use each entry.
- **Still a normal KDBX file.** KeePassXC, KeePassDX, KeePassium… open it with
  the key file, so phones and other tools keep working.

## How it works

```text
main.kdbx                 key file only (KeePass XML 2.0, same as KeePassXC writes)
main.kdbx.slots/<id>.json one per device: AES-256-GCM(key file) under
                          HKDF(hmac-secret(credential, salt)); fields bound as AAD
```

Unlocking probes each connected authenticator silently (`up=false`) for the
slot credentials it owns, then asks only that one for `hmac-secret` with user
verification. Slots are separate files so devices syncing the folder (e.g.
Syncthing) never conflict.

A per-database **agent** (started on demand) holds the unlocked database for
10 minutes idle / 8 hours at most, reloads it when the file changes, and does
all secret handling: copies go to the Wayland clipboard marked sensitive
(`x-kde-passwordManagerHint`) and are cleared after 20 s. The popup itself never
sees a password. The agent's socket is per-user (0700, peer uid checked) and the
process is non-dumpable.

## Setup

```sh
# Generate the key file and this device's slot (two fingerprints).
pkee --db ~/Sync/main.kdbx init --keyfile-out ./main.keyx
# Switch the database to that key file (asks for the current password).
keepassxc-cli db-edit --set-key-file ./main.keyx --unset-password ~/Sync/main.kdbx
pkee --db ~/Sync/main.kdbx check
```

Back the key file up offline; it is also what other apps (phone) use. More
devices: `pkee keyfile | ssh other pkee slot add --keyfile -`.

## Use

`pkee` (or `PKEE_DB=… pkee`) opens the popup:

| Key | |
|---|---|
| type | search |
| ↑ ↓, Ctrl+N/P | move |
| Enter | entry details (Esc: back) |
| Ctrl+C / Ctrl+B / Ctrl+T | copy password / username / TOTP code |
| Ctrl+O | open URL |
| Esc | close |

From scripts: `pkee get <query> [--field password|username|totp|url] [--print]`,
`pkee status`, `pkee lock`, `pkee slot list|add|rm`.

## Nix

```nix
inputs.pkee.url = "github:koxu1996/pkee";
# Home Manager
imports = [ inputs.pkee.homeManagerModules.default ];
programs.pkee = { enable = true; database = "/home/me/Sync/main.kdbx"; };
```

Hyprland: `windowrule` on class `pkee` to float it, and a bind to run
`pkee --db …` (session variables may not reach the compositor).

`nix develop` gives a shell for `cargo build` / `cargo test`.
