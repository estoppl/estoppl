// STD.4 — Standing Certificate offline verification.
//
// `estoppl verify-certificate <cert.json>` reads a Standing Certificate JSON
// file, fetches the issuer's public key (from JWKS or a local file), and
// verifies the Ed25519 signature over the canonical JSON of the signable
// subset of fields.
//
// Canonical JSON contract (must match the Go side in
// estoppl/api/internal/api/signing.go):
//   - Build a sorted-key BTreeMap of the signable fields
//   - Serialize to compact JSON (serde_json default)
//   - Use only int / string / bool / nested-string-keyed-map values
//
// The signable payload deliberately excludes:
//   - The signature field itself.
//   - The full subscore inputs map (contains floats; floats format
//     inconsistently across languages). The subscore VALUES are signed.
//   - Cosmetic fields (verify_command, methodology_url).

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Verify a Standing Certificate. Prints VALID + summary on success, returns
/// Err with the failure reason on any check failure.
pub async fn cmd_verify_certificate(
    cert_path: &Path,
    jwks_url: &str,
    pubkey_file: Option<&PathBuf>,
) -> Result<()> {
    let cert_json = std::fs::read_to_string(cert_path)
        .with_context(|| format!("Failed to read certificate: {}", cert_path.display()))?;
    let cert: Value =
        serde_json::from_str(&cert_json).with_context(|| "Certificate file is not valid JSON")?;

    let public_key_id = cert
        .get("public_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("certificate missing required field: public_key_id"))?;

    let signature_b64 = cert
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("certificate missing required field: signature (unsigned cert?)"))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .context("signature is not valid base64")?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!(
            "signature wrong length: want 64 bytes (Ed25519), got {}",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let pubkey = if let Some(path) = pubkey_file {
        load_pubkey_from_file(path)?
    } else {
        fetch_pubkey_from_jwks(jwks_url, public_key_id).await?
    };

    let canonical = build_signable_canonical_json(&cert)?;

    pubkey
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| {
            anyhow!(
                "signature INVALID: {} — cert may be tampered or signed by a different key",
                e
            )
        })?;

    println!("VALID");
    println!(
        "  certificate_id:      {}",
        str_field(&cert, "certificate_id")
    );
    println!("  deployer_id:         {}", str_field(&cert, "deployer_id"));
    println!(
        "  deployer_name:       {}",
        str_field(&cert, "deployer_name")
    );
    println!(
        "  score:               {} ({})",
        cert.get("score").map(|v| v.to_string()).unwrap_or_default(),
        str_field(&cert, "score_band")
    );
    println!(
        "  subscores:           gov={} scope={} anomaly={}",
        cert.pointer("/subscores/governance_discipline/value")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        cert.pointer("/subscores/scope_adherence/value")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        cert.pointer("/subscores/anomaly_load/value")
            .map(|v| v.to_string())
            .unwrap_or_default()
    );
    println!(
        "  methodology_version: {}",
        str_field(&cert, "methodology_version")
    );
    println!(
        "  aarm_version:        {}",
        str_field(&cert, "aarm_version")
    );
    println!("  issued_at:           {}", str_field(&cert, "issued_at"));
    println!("  valid_until:         {}", str_field(&cert, "valid_until"));
    println!("  signed_by_kid:       {}", public_key_id);
    println!(
        "  evidence_url:        {}",
        str_field(&cert, "evidence_url")
    );

    Ok(())
}

fn str_field<'a>(cert: &'a Value, field: &str) -> &'a str {
    cert.get(field).and_then(|v| v.as_str()).unwrap_or("?")
}

/// Build the canonical JSON bytes that the Go side signed. Must produce
/// byte-identical output to the Go signCertificate() payload map.
fn build_signable_canonical_json(cert: &Value) -> Result<String> {
    let mut payload: BTreeMap<&'static str, Value> = BTreeMap::new();

    payload.insert(
        "certificate_id",
        cert.get("certificate_id").cloned().unwrap_or_default(),
    );
    payload.insert(
        "deployer_id",
        cert.get("deployer_id").cloned().unwrap_or_default(),
    );
    // deployer_name uses omitempty on the Go side; if absent, sign as empty string
    payload.insert(
        "deployer_name",
        cert.get("deployer_name").cloned().unwrap_or(json!("")),
    );
    payload.insert("score", cert.get("score").cloned().unwrap_or(json!(0)));
    payload.insert(
        "score_band",
        cert.get("score_band").cloned().unwrap_or_default(),
    );
    payload.insert(
        "subscore_governance",
        cert.pointer("/subscores/governance_discipline/value")
            .cloned()
            .unwrap_or(json!(0)),
    );
    payload.insert(
        "subscore_scope",
        cert.pointer("/subscores/scope_adherence/value")
            .cloned()
            .unwrap_or(json!(0)),
    );
    payload.insert(
        "subscore_anomaly",
        cert.pointer("/subscores/anomaly_load/value")
            .cloned()
            .unwrap_or(json!(0)),
    );
    payload.insert(
        "methodology_version",
        cert.get("methodology_version").cloned().unwrap_or_default(),
    );
    payload.insert(
        "aarm_version",
        cert.get("aarm_version").cloned().unwrap_or_default(),
    );
    payload.insert(
        "aarm_conformance",
        cert.get("aarm_conformance").cloned().unwrap_or_default(),
    );
    payload.insert(
        "evidence_url",
        cert.get("evidence_url").cloned().unwrap_or_default(),
    );
    payload.insert(
        "issued_at",
        cert.get("issued_at").cloned().unwrap_or_default(),
    );
    payload.insert(
        "valid_until",
        cert.get("valid_until").cloned().unwrap_or_default(),
    );
    payload.insert(
        "public_key_id",
        cert.get("public_key_id").cloned().unwrap_or_default(),
    );

    // BTreeMap iterates in sorted-key order; serde_json::to_string produces
    // compact JSON (no whitespace). This matches Go's canonicalJSON in
    // signing.go exactly.
    serde_json::to_string(&payload).context("failed to canonicalize payload")
}

fn load_pubkey_from_file(path: &Path) -> Result<VerifyingKey> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read public key file: {}", path.display()))?;
    let trimmed = content.trim();

    // Accept either raw 32-byte file (binary or hex) or base64.
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed).context("public key hex decode failed")?
    } else if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        b
    } else if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed) {
        b
    } else {
        std::fs::read(path).with_context(|| "Failed to read public key as raw bytes")?
    };

    if bytes.len() != 32 {
        return Err(anyhow!(
            "public key wrong length: want 32 bytes (Ed25519), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("failed to parse Ed25519 public key")
}

async fn fetch_pubkey_from_jwks(jwks_url: &str, kid: &str) -> Result<VerifyingKey> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(jwks_url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch JWKS from {}", jwks_url))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("JWKS fetch returned {}", status));
    }
    let jwks: Value = resp
        .json()
        .await
        .context("JWKS response is not valid JSON")?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("JWKS has no 'keys' array"))?;

    let matching = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
        .ok_or_else(|| {
            anyhow!(
                "no JWK matches kid={} (cert may reference a key the issuer rotated out)",
                kid
            )
        })?;

    let alg = matching.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let crv = matching.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "EdDSA" || crv != "Ed25519" {
        return Err(anyhow!(
            "JWK kid={} has unexpected alg={} crv={}; want EdDSA / Ed25519",
            kid,
            alg,
            crv
        ));
    }

    let x = matching
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("JWK kid={} missing 'x' field", kid))?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(x))
        .context("JWK 'x' is not valid base64url")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "JWK 'x' wrong length: want 32 bytes (Ed25519), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("failed to parse Ed25519 public key from JWK")
}
