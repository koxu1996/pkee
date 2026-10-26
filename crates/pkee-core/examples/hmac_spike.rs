//! Spike: does linux-passkey give a stable `hmac-secret` through ctap-hid-fido2?
//!
//! Creates a throwaway credential for RP "pkee", then asks for the secret twice
//! with the same salt and once with another. Expect four fingerprint prompts
//! (one to create, three to use).
//!
//!     cargo run -p pkee-core --example hmac_spike [device-index]

use anyhow::{Result, bail};
use pkee_core::fido::{self, Authenticator};

fn main() -> Result<()> {
    let devs = fido::authenticators();
    if devs.is_empty() {
        bail!("no FIDO2 device with hmac-secret + uv found (is linux-passkey running? hidraw access?)");
    }
    for (i, d) in devs.iter().enumerate() {
        println!("[{i}] {}", d.name());
    }
    let idx: usize = std::env::args().nth(1).map_or(Ok(0), |s| s.parse())?;
    let Some(dev) = devs.get(idx) else { bail!("no device {idx}") };
    println!("using [{idx}] {}\n", dev.name());

    println!("1/4 create credential: approve + fingerprint…");
    let cred = dev.create_credential("hmac-spike (throwaway)")?;
    println!("    credential id: {} bytes", cred.len());

    let salt_a = fido::random::<32>()?;
    let salt_b = fido::random::<32>()?;

    println!("2/4 hmac-secret(salt A): approve + fingerprint…");
    let a1 = dev.hmac_secret(&cred, &salt_a)?;
    println!("    {}…", short(&a1));

    println!("3/4 hmac-secret(salt A) again: approve + fingerprint…");
    let a2 = dev.hmac_secret(&cred, &salt_a)?;
    println!("    {}…", short(&a2));

    println!("4/4 hmac-secret(salt B): approve + fingerprint…");
    let b = dev.hmac_secret(&cred, &salt_b)?;
    println!("    {}…", short(&b));

    println!();
    check("same salt -> same secret", *a1 == *a2);
    check("other salt -> other secret", *a1 != *b);
    Ok(())
}

fn short(s: &[u8; 32]) -> String {
    s[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn check(what: &str, ok: bool) {
    println!("{} {what}", if ok { "PASS" } else { "FAIL" });
}
