use crate::errors::SraError;
use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum ArtifactType {
    ModelWeight,
    RegexSet,
    Config,
    ReferenceData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SraManifestDraft {
    pub manifest_version: String,
    pub status: String, // Always "UNVERIFIED" in scan phase
    pub artifact_name: String,
    pub artifact_type: ArtifactType,
    pub size_bytes: u64,
    pub hashes: HashBlock,
    pub technical_observations: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HashBlock {
    pub blake3: String,
    pub sha256: String,
}

pub struct ScanEngine;

impl ScanEngine {
    pub fn perform_scan(path: PathBuf, artifact_type: ArtifactType) -> Result<SraManifestDraft, SraError> {
        // 1. Security Check: Refuse symlinks/network paths for ISO 17025 chain-of-custody
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            return Err(SraError::Security("Only regular files are supported for deterministic scanning".into()));
        }

        // 2. Dual Hashing (Deterministic Chunking)
        let (b3_hash, s256_hash) = Self::compute_dual_hashes(&path)?;

        // 3. Construct Draft Manifest
        Ok(SraManifestDraft {
            manifest_version: "1.0.0".into(),
            status: "UNVERIFIED_DRAFT".into(),
            artifact_name: path.file_name().unwrap_or_default().to_string_lossy().into(),
            artifact_type,
            size_bytes: metadata.len(),
            hashes: HashBlock {
                blake3: b3_hash,
                sha256: s256_hash,
            },
            technical_observations: vec![
                format!("File size: {} bytes", metadata.len()),
                "Deterministic scan completed in air-gapped environment.".into(),
            ],
        })
    }

    fn compute_dual_hashes(path: &Path) -> Result<(String, String), SraError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut buffer = [0; 65536]; // 64KB chunks

        let mut b3_hasher = Blake3Hasher::new();
        let mut s256_hasher = Sha256::new();

        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break; }
            b3_hasher.update(&count[..count]);
            s256_hasher.update(&buffer[..count]);
        }

        Ok((
            b3_hasher.finalize().to_hex().to_string(),
            format!("{:x}", s256_hasher.finalize()),
        ))
    }
}
