import subprocess
import csv
import json
import os
import uuid
import requests
from collections import Counter

# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

INTERFACE = "eth0"              # Change if needed (check with: ip a)
CAPTURE_DURATION = 100          # seconds
THRESHOLD = 40                  # Packet threshold

PCAP_FILE = "traffic.pcap"
CSV_FILE = "traffic.csv"
ALERT_FILE = "alert.json"
VERDICT_FILE = "verdict.json"

# ---- Ollama Config ----
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:7b"    # change to qwen2.5:7b or llama3.2:3b if needed

# Metadata
DESTINATION_HOST = "Internal-server"
DESTINATION_IP = "10.0.2.15"

SYSTEM_PROMPT = (
    "You are a SOC (Security Operations Center) analyst assistant. "
    "You will be given a JSON alert describing anomalous network traffic "
    "detected on a monitored host. Analyze the evidence and respond ONLY "
    "with a valid JSON object, no extra text, no markdown, no explanation "
    "outside the JSON. Use exactly this format:\n\n"
    "{\n"
    '  "verdict": "benign" | "suspicious" | "malicious",\n'
    '  "confidence": <integer 0-100>,\n'
    '  "reasoning": "<short explanation, 2-3 sentences>",\n'
    '  "recommended_action": "<short recommended next step for the analyst>"\n'
    "}"
)


# ------------------------------------------------
# HELPER
# ------------------------------------------------

def run_command(cmd, description):
    print(f"[+] {description}")
    subprocess.run(cmd, check=True)


# ------------------------------------------------
# STEP 1 - Capture Traffic
# ------------------------------------------------

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", "icmp and dst host 10.0.2.15",
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    run_command(capture_cmd, f"Capturing on {INTERFACE} for {CAPTURE_DURATION}s")

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed.")

    print(f"[+] Capture saved to {PCAP_FILE}")


# ------------------------------------------------
# STEP 2 - Convert to CSV
# ------------------------------------------------

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    print(f"[+] CSV created at {CSV_FILE}")


# ------------------------------------------------
# STEP 3 - Analyze Traffic
# ------------------------------------------------

def analyze_traffic():
    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    print("\n[+] Traffic volume per source IP:\n")
    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")

    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            print(f"\n[!] Suspicious IP detected: {ip}")
            return ip, count

    print("\n[+] No suspicious activity detected.")
    return None, None


# ------------------------------------------------
# STEP 4 - Generate Alert JSON
# ------------------------------------------------

def generate_alert(ip, count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "alert_type": "Suspicious Network Volume",
        "indicator_type": "ip",
        "indicator_value": ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "evidence": {
            "packet_count": count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },
        "analyst_question": "Is this expected activity or suspicious scanning/noise?"
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"[+] Alert JSON written to {ALERT_FILE}")
    return alert


# ------------------------------------------------
# STEP 5 - Send to Ollama (local model) for Triage
# ------------------------------------------------

def send_to_ollama(alert):
    print(f"[+] Sending alert to local Ollama model ({OLLAMA_MODEL}) for triage...")

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(alert, indent=2)}
        ],
        "format": "json",   # tells Ollama to constrain output to valid JSON
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Could not connect to Ollama. Is it running? Try 'ollama serve' "
            "in another terminal, or check 'curl http://localhost:11434'."
        )

    data = response.json()
    raw_output = data.get("message", {}).get("content", "")

    print("[+] Ollama raw response:")
    print(raw_output)

    try:
        verdict = json.loads(raw_output)
    except json.JSONDecodeError:
        print("[!] Warning: model did not return valid JSON. Storing raw text instead.")
        verdict = {"raw_response": raw_output}

    combined = {
        "alert": alert,
        "ai_verdict": verdict
    }

    with open(VERDICT_FILE, "w") as f:
        json.dump(combined, f, indent=4)

    print(f"[+] Verdict written to {VERDICT_FILE}")

    if isinstance(verdict, dict) and "verdict" in verdict:
        print(f"\n[+] Verdict: {str(verdict['verdict']).upper()} "
              f"(confidence: {verdict.get('confidence', 'N/A')}%)")
        print(f"[+] Reasoning: {verdict.get('reasoning', 'N/A')}")
        print(f"[+] Recommended action: {verdict.get('recommended_action', 'N/A')}")

    return verdict


# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    try:
        capture_traffic()
        convert_to_csv()
        ip, count = analyze_traffic()

        if ip:
            alert = generate_alert(ip, count)
            send_to_ollama(alert)
        else:
            print("[+] No alert generated, nothing sent to Ollama.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()
