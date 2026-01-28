use crate::errors::SraError;
use crate::scan::{SraManifestDraft, HashBlock};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, Signer, Signature};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct PractitionerIdentity {
    pub id: String,
    pub role: String,
    pub organization: String,
    pub jurisdiction: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationBlock {
    pub declaration: String,
    pub practitioner: PractitionerIdentity,
    pub signature: String, // Base64 encoded Ed25519
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FinalSraManifest {
    pub manifest_version: String,
    pub status: String, // SEALED_ATTESTED
    pub artifact_name: String,
    pub hashes: HashBlock,
    pub technical_observations: Vec<String>,
    pub attestation: AttestationBlock,
}

pub struct ExportEngine;

impl ExportEngine {
    pub fn export_and_seal(
        verified_path: PathBuf, 
        identity: PractitionerIdentity,
        keypair: &Keypair
    ) -> Result<FinalSraManifest, SraError> {
        let content = std::fs::read_to_string(&verified_path)?;
        let verified: SraManifestDraft = serde_json::from_str(&content)
            .map_err(|_| SraError::SchemaViolation("Invalid verified manifest format".into()))?;

        // 1. Input Gate: Strict Status Check
        if verified.status != "VERIFIED_METHOD" {
            return Err(SraError::StatusConflict {
                expected: "VERIFIED_METHOD".into(),
                found: verified.status,
            });
        }

        // 2. Prepare Legal Declaration (FSR/ISO 17025 compliant)
        let declaration = "I attest that this artifact has been verified as fit for forensic use \
                           under ISO/IEC 17025 and is suitable for use within the stated jurisdiction. \
                           This attestation does not assert evidential truth, only method suitability.".to_string();

        // 3. Cryptographic Sealing
        // We sign the JSON representation of the verified draft to ensure integrity
        let message = serde_json::to_vec(&verified).unwrap();
        let signature: Signature = keypair.sign(&message);

        // 4. Construct Final Artifact
        Ok(FinalSraManifest {
            manifest_version: verified.manifest_version,
            status: "SEALED_ATTESTED".into(),
            artifact_name: verified.artifact_name,
            hashes: verified.hashes,
            technical_observations: verified.technical_observations,
            attestation: AttestationBlock {
                declaration,
                practitioner: identity,
                signature: base64::encode(signature.to_bytes()),
                public_key: base64::encode(keypair.public.to_bytes()),
            },
        })
    }
}
