//! FIDO2 `hmac-secret`: where a slot's wrapping secret comes from.
//!
//! A slot holds a non-discoverable credential created for [`RP_ID`] and a random
//! salt. Asking the authenticator for `hmac-secret` with that salt (and user
//! verification, i.e. the fingerprint on linux-passkey) gives back the same 32
//! bytes every time; the slot's key is derived from them.

use anyhow::{Context, Result, anyhow, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as AssertExt;
use ctap_hid_fido2::fidokey::make_credential::Extension as CredExt;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHid, LibCfg};
use zeroize::Zeroizing;

/// Relying party ID for pkee's credentials. Not a web origin, so it can never
/// collide with a site's passkeys.
pub const RP_ID: &str = "pkee";

/// Something that can turn (credential, salt) into a stable secret. Kept narrow
/// so another CTAP client (e.g. libfido2) can stand in for `ctap-hid-fido2`.
pub trait Authenticator {
    /// Human-readable device name, for prompts and slot labels.
    fn name(&self) -> &str;
    /// Create a new `hmac-secret` credential (user verification required) and
    /// return its ID. `label` is the user name the authenticator shows in its
    /// prompt, e.g. "main.kdbx (MacBook Air)".
    fn create_credential(&self, label: &str) -> Result<Vec<u8>>;
    /// Whether `cred_id` belongs to this device. Silent: no presence or
    /// verification, so no prompt. Needed because OpenSK verifies the user
    /// *before* looking the credential up, so a wrong guess costs a fingerprint.
    fn owns(&self, cred_id: &[u8]) -> Result<bool>;
    /// The `hmac-secret` output for `salt` under credential `cred_id`, with user
    /// verification. Fails if the credential does not belong to this device.
    fn hmac_secret(&self, cred_id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>;
}

/// A FIDO2 authenticator on hidraw.
pub struct HidAuthenticator {
    name: String,
    dev: FidoKeyHid,
}

/// Every FIDO HID device that advertises `hmac-secret` and built-in user
/// verification. Devices that can't be opened or don't qualify are skipped.
pub fn authenticators() -> Vec<HidAuthenticator> {
    let cfg = LibCfg {
        // The default prints "touch the sensor" to stdout; callers show their own prompt.
        enable_keep_alive_msg: false,
        ..LibCfg::init()
    };
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .filter_map(|info| {
            let name = if info.product_string.is_empty() {
                info.info.clone()
            } else {
                info.product_string.clone()
            };
            let mut dev = FidoKeyHid::new(&[info.param], &cfg).ok()?;
            let info = dev.get_info().ok()?;
            let has = |opt: &str| info.options.iter().any(|(k, v)| k == opt && *v);
            if !info.extensions.iter().any(|e| e == "hmac-secret") || !has("uv") {
                return None;
            }
            // Protocol two (HKDF-based) when offered; one otherwise.
            dev.set_pin_uv_auth_protocol_two().ok()?;
            Some(HidAuthenticator { name, dev })
        })
        .collect()
}

impl Authenticator for HidAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn create_credential(&self, label: &str) -> Result<Vec<u8>> {
        let challenge = random::<32>()?;
        // Without a user entity ctap-hid-fido2 sends a name of " ".
        let user_id = random::<16>()?;
        let user = PublicKeyCredentialUserEntity::new(Some(&user_id), Some(label), Some(label));
        let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
            .user_entity(&user)
            .extensions(&[CredExt::HmacSecret(Some(true))])
            .build();
        let att = self
            .dev
            .make_credential_with_args(&args)
            .context("makeCredential")?;
        if !att.flags.user_verified_result {
            bail!("authenticator created the credential without user verification");
        }
        if !att
            .extensions
            .iter()
            .any(|e| matches!(e, CredExt::HmacSecret(Some(true))))
        {
            bail!("authenticator did not enable hmac-secret for the credential");
        }
        Ok(att.credential_descriptor.id)
    }

    fn owns(&self, cred_id: &[u8]) -> Result<bool> {
        let challenge = random::<32>()?;
        let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
            .credential_id(cred_id)
            .without_pin_and_uv()
            .without_up()
            .build();
        match self.dev.get_assertion_with_args(&args) {
            Ok(_) => Ok(true),
            // ctap-hid-fido2 only reports the CTAP status as text.
            Err(e) if format!("{e:#}").contains("CTAP2_ERR_NO_CREDENTIALS") => Ok(false),
            Err(e) => Err(e.context("getAssertion (probe)")),
        }
    }

    fn hmac_secret(&self, cred_id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let challenge = random::<32>()?;
        let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
            .credential_id(cred_id)
            .extensions(&[AssertExt::HmacSecret(Some(*salt))])
            .build();
        let assertions = self
            .dev
            .get_assertion_with_args(&args)
            .context("getAssertion")?;
        let ass = assertions
            .first()
            .ok_or_else(|| anyhow!("getAssertion returned no assertion"))?;
        // CTAP 2.1 derives a different secret with and without UV: a slot must
        // only ever be opened with it.
        if !ass.flags.user_verified_result {
            bail!("authenticator answered without user verification");
        }
        ass.extensions
            .iter()
            .find_map(|e| match e {
                AssertExt::HmacSecret(Some(out)) => Some(Zeroizing::new(*out)),
                _ => None,
            })
            .ok_or_else(|| anyhow!("authenticator returned no hmac-secret output"))
    }
}

/// `N` bytes from the OS RNG.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("getrandom: {e}"))?;
    Ok(buf)
}
