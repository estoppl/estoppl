use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

/// Manages Ed25519 keypair for signing audit events.
pub struct KeyManager {
    signing_key: SigningKey,
    pub key_id: String,
}

impl KeyManager {
    /// Load an existing keypair from disk, or generate a new one.
    pub fn load_or_generate(key_dir: &Path) -> Result<Self> {
        let private_path = key_dir.join("estoppl-signing.key");
        let public_path = key_dir.join("estoppl-signing.pub");

        let signing_key = if private_path.exists() {
            let bytes = std::fs::read(&private_path)
                .context("Failed to read signing key")?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key file: expected 32 bytes"))?;
            SigningKey::from_bytes(&key_bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::create_dir_all(key_dir)
                .context("Failed to create key directory")?;
            std::fs::write(&private_path, key.to_bytes())
                .context("Failed to write signing key")?;
            std::fs::write(&public_path, key.verifying_key().to_bytes())
                .context("Failed to write public key")?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))?;
            }

            tracing::info!("Generated new Ed25519 keypair at {}", key_dir.display());
            key
        };

        let key_id = hex::encode(&signing_key.verifying_key().to_bytes()[..8]);

        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Sign arbitrary bytes, returning the base64-encoded signature.
    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes())
    }

    /// Return the public verifying key (used for signature verification).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    #[test]
    fn generate_and_load_keypair() {
        let dir = TempDir::new().unwrap();
        let key_dir = dir.path().join("keys");

        // Generate new keypair.
        let km1 = KeyManager::load_or_generate(&key_dir).unwrap();
        assert!(!km1.key_id.is_empty());

        // Load existing keypair — should get the same key_id.
        let km2 = KeyManager::load_or_generate(&key_dir).unwrap();
        assert_eq!(km1.key_id, km2.key_id);
    }

    #[test]
    fn sign_and_verify() {
        let dir = TempDir::new().unwrap();
        let km = KeyManager::load_or_generate(dir.path()).unwrap();

        let data = b"test message for signing";
        let sig_b64 = km.sign(data);

        // Decode signature and verify.
        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig_b64,
        ).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap(),
        );

        km.verifying_key().verify(data, &signature).unwrap();
    }

    #[test]
    fn sign_different_data_produces_different_signatures() {
        let dir = TempDir::new().unwrap();
        let km = KeyManager::load_or_generate(dir.path()).unwrap();

        let sig1 = km.sign(b"message one");
        let sig2 = km.sign(b"message two");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn key_files_created_on_disk() {
        let dir = TempDir::new().unwrap();
        let key_dir = dir.path().join("keys");

        KeyManager::load_or_generate(&key_dir).unwrap();

        assert!(key_dir.join("estoppl-signing.key").exists());
        assert!(key_dir.join("estoppl-signing.pub").exists());

        // Private key should be 32 bytes.
        let key_bytes = std::fs::read(key_dir.join("estoppl-signing.key")).unwrap();
        assert_eq!(key_bytes.len(), 32);

        // Public key should be 32 bytes.
        let pub_bytes = std::fs::read(key_dir.join("estoppl-signing.pub")).unwrap();
        assert_eq!(pub_bytes.len(), 32);
    }
}
