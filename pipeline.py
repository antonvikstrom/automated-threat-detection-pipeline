import time
from modules.attack_module import trigger_dns_exfiltration, trigger_path_traversal
from modules.splunk_module import check_splunk_detection
from modules.threat_intel import check_ip_reputation


def run_full_pipeline(): 
    print("==================================================")
    print("  AUTOMATED DETECTION & ENRICHMENT PIPELINE")
    print("==================================================")

    # ----------------------------------------------------
    # Step 1: Attack Emulation
    # ----------------------------------------------------
    print("\n--- STEP 1: OFFENSIVE ATTACK EMULATION ---")
    trigger_path_traversal()
    trigger_dns_exfiltration()

    # Pause for log ingestion into Splunk
    print("\n[*] Waiting 8 seconds for Splunk log ingestion...")
    time.sleep(8)

    # ----------------------------------------------------
    # Step 2: SIEM Detection Verification
    # ----------------------------------------------------
    print("\n--- STEP 2: SIEM DETECTION AUDIT ---")
    detected_ip = check_splunk_detection(
        spl_query='index=* "etc/passwd"', search_name="Web Path Traversal"
    )

    # ----------------------------------------------------
    # Step 3: Threat Intelligence Enrichment
    # ----------------------------------------------------
    print("\n--- STEP 3: THREAT INTEL ENRICHMENT ---")
    if detected_ip:
        check_ip_reputation(detected_ip)
    else:
        print("    [-] Skipping enrichment: No attacker IP extracted.")

    print("\n==================================================")
    print("  PIPELINE EXECUTION COMPLETE")
    print("==================================================")


if __name__ == "__main__":
    run_full_pipeline()