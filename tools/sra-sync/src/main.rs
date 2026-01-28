mod export;
use export::{ExportEngine, PractitionerIdentity};
// Note: In a real air-gapped tool, key management would be handled via secure hardware or encrypted local storage.

#[derive(Subcommand)]
enum Commands {
    // ... scan, verify ...
    Export {
        #[arg(short, long)]
        verified: PathBuf,
        #[arg(long)]
        practitioner_id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        // ...
        Commands::Export { verified, practitioner_id } => {
            // Simulated loading of practitioner keypair
            let keypair = load_practitioner_key(); 
            
            let identity = PractitionerIdentity {
                id: practitioner_id,
                role: "Principal Digital Forensics Architect".into(),
                organization: "Aletheia Oversight Group".into(),
                jurisdiction: "UK (FSR v2)".into(),
            };

            match ExportEngine::export_and_seal(verified.clone(), identity, &keypair) {
                Ok(final_sra) => {
                    let mut out_path = verified;
                    out_path.set_extension("sram");
                    let json = serde_json::to_string_pretty(&final_sra).unwrap();
                    std::fs::write(&out_path, json).expect("Write failure");
                    
                    println!("--- EXPORT SUCCESSFUL ---");
                    println!("Status: SEALED_ATTESTED");
                    println!("Artifact: {:?}", out_path.file_name().unwrap());
                    println!("Practitioner: {} ({})", final_sra.attestation.practitioner.id, final_sra.attestation.practitioner.role);
                    println!("NOTE: This file is now READ-ONLY for legal integrity.");
                }
                Err(e) => eprintln!("Export Failed: {}", e),
            }
        }
    }
}
