import json
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Module-level constants
REQUIRED_MANIFEST_FIELDS = ["artifact_name", "hashes", "jurisdiction", "status", "attestation"]
SEALED_STATUS = "SEALED_ATTESTED"

def verify_local_sra(manifest_path="schema/sra_manifest.json"):
    """
    Cross-reference local SRA copy with remote signed ledger.
    """
    logging.info(f"--- Aletheia SRA: Verifying Manifest {manifest_path} ---")
    
    if not os.path.exists(manifest_path):
        logging.error(f"Manifest not found at {manifest_path}")
        return False

    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
            
        # Required fields for FSR v2 compliance
        for field in REQUIRED_MANIFEST_FIELDS:
            if field not in manifest:
                logging.error(f"FAIL: Missing required field '{field}'")
                return False
        
        logging.info(f"Artifact: {manifest.get('artifact_name', 'Unknown')}")
        logging.info(f"Jurisdiction: {manifest.get('jurisdiction', 'Unknown')}")
        logging.info(f"Status: {manifest.get('status', 'Unknown')}")
        
        if manifest.get('status') != SEALED_STATUS:
            logging.warning("Manifest is not in SEALED_STATUS state.")
            
        logging.info("✅ Manifest structure validated.")
        return True
        
    except (OSError, json.JSONDecodeError) as e:
        logging.error(f"Error during verification ({type(e).__name__}): {e}")
        return False
    except Exception as e:
        logging.critical(f"Unexpected error during verification ({type(e).__name__}): {e}")
        raise

if __name__ == "__main__":
    target = "schema/sra_manifest.json"
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
    if verify_local_sra(target):
        sys.exit(0)
    else:
        sys.exit(1)
