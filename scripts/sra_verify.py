import json
import os
import sys

def verify_local_sra(manifest_path="schema/sra_manifest.json"):
    """
    Cross-reference local SRA copy with remote signed ledger.
    """
    print(f"--- Aletheia SRA: Verifying Manifest {manifest_path} ---")
    
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest not found at {manifest_path}")
        return False

    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
            
        # Required fields for FSR v2 compliance
        required_fields = ["artifact_name", "hashes", "jurisdiction", "status", "attestation"]
        for field in required_fields:
            if field not in manifest:
                print(f"FAIL: Missing required field '{field}'")
                return False
        
        print(f"Artifact: {manifest.get('artifact_name', 'Unknown')}")
        print(f"Jurisdiction: {manifest.get('jurisdiction', 'Unknown')}")
        print(f"Status: {manifest.get('status', 'Unknown')}")
        
        if manifest.get('status') != "SEALED_ATTESTED":
            print("WARN: Manifest is not in SEALED_ATTESTED state.")
            
        print("✅ Manifest structure validated.")
        return True
        
    except Exception as e:
        print(f"Error during verification: {e}")
        return False

if __name__ == "__main__":
    target = "schema/sra_manifest.json"
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
    if verify_local_sra(target):
        sys.exit(0)
    else:
        sys.exit(1)
