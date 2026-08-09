# AI-Powered SOC Alert Triage Pipeline

An offline SOC (Security Operations Center) automation tool that captures live network traffic, detects anomalous packet volume from a source IP using `tshark`, and sends the resulting alert to a **locally-hosted LLM (Qwen2.5:7b via Ollama)** for automated triage. The model returns a structured JSON verdict — classification, confidence score, reasoning, and a recommended next action — with **no external API calls and no internet dependency**, making it suitable for air-gapped or isolated lab environments.

Attacker VM: Ubuntu

Monitoring/Attacked VM : Kali 

---

## Architecture / Workflow

```
[Attacker/Traffic VM] --(ICMP traffic)--> [Monitored VM: tshark capture]
                                                |
                                                v
                                    Traffic analysis (packet count per source IP)
                                                |
                                                v
                                    Threshold exceeded? --> alert.json generated
                                                |
                                                v
                                    Sent to local Ollama (Qwen2.5:7b)
                                                |
                                                v
                                    AI verdict returned --> verdict.json
```

- **Capture & convert:** `tshark` captures ICMP traffic on a chosen interface and converts it to CSV.
- **Analyze:** Packet counts are tallied per source IP; any IP exceeding the configured threshold is flagged.
- **Alert generation:** A structured `alert.json` is created with the suspicious IP, packet count, and metadata.
- **AI triage:** The alert is sent to a local Ollama model, which returns a verdict (`benign` / `suspicious` / `malicious`), a confidence score, reasoning, and a recommended action.
- **Output:** Combined alert + verdict is saved to `verdict.json`.

---

## Requirements

### Software
| Tool | Purpose | Install |
|---|---|---|
| Ubuntu | Attacker/Analyser (as per choice) | Virtual Machine |
| Kali | Attacker/Analyser (as per choice) | Virtual Machine |
| Python 3.10+ | Runs the main script | Pre-installed on Kali/Ubuntu |
| Wireshark/tshark | Packet capture | `sudo apt install tshark` |
| Ollama | Local LLM runtime | `curl -fsSL https://ollama.com/install.sh \| sh` |
| Python `requests` | HTTP calls to Ollama's local API | `pip install requests --break-system-packages` |

### Hardware / VM notes
- Ollama inference is CPU-bound in most VM setups (no GPU passthrough). Allocate **at least 8 GB RAM** to the VM running Ollama for `qwen2.5:7b` to load reliably without triggering the OOM killer.
- Two VMs are used in this lab setup:
  - **Monitoring VM** (e.g., Kali) — runs `tshark`, the Python script, and Ollama.
  - **Traffic-source VM** (e.g., Ubuntu) — generates ICMP traffic toward the monitoring VM.

### Model
This project uses:
```
qwen2.5:7b
```
Qwen2.5 was chosen over similarly-sized Llama models for its more reliable structured JSON output, which this pipeline depends on for parsing verdicts programmatically.

Pull it with:
```bash
ollama pull qwen2.5:7b
```

Lighter alternative if your VM has limited RAM (~2-3 GB free):
```bash
ollama pull llama3.2:3b
```

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

### 2. Install dependencies
```bash
sudo apt update
sudo apt install tshark -y
pip install requests --break-system-packages
```

### 3. Install and configure Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b
```

Confirm the Ollama service is running:
```bash
curl http://localhost:11434
```
Expected output: `Ollama is running`

> **Note:** On some systems, Ollama installs as a `systemd` service and starts automatically. Check with `systemctl status ollama`. Do not also run `ollama serve` manually if the service is already active — this causes a port conflict.

### 4. Configure networking between VMs

Both VMs must be able to reach each other. **Plain NAT mode in VirtualBox will not work**, since it isolates each VM from the others. Use one of the following instead:

- **NAT Network** *(recommended — keeps internet access on both VMs)*
  VirtualBox → File → Preferences → Network → NAT Networks → Add a network, then set both VMs' Adapter 1 to **Attached to: NAT Network** using that same network name.
- **Internal Network** *(simpler, no internet access needed for the VMs)*
  Set both VMs' Adapter 1 to **Attached to: Internal Network** with the same network name (e.g., `intnet`).

After switching network modes, restart both VMs.

### 5. Find each VM's IP address
On **each** VM:
```bash
ip a
```
Look for the `inet` address under the active interface (commonly `eth0`).

Example from this lab setup:
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
```

### 6. Update the script configuration
Open `AI_Soc_Analyst.py` and update these values to match **the monitoring VM's own IP** (the machine tshark is running on — traffic must be addressed *to* this machine):

```python
INTERFACE = "eth0"                  # confirm with `ip a` on the monitoring VM
CAPTURE_DURATION = 100              # seconds
THRESHOLD = 40                      # packet count that triggers an alert
DESTINATION_IP = "10.0.2.15"        # <-- set to the monitoring VM's own IP
OLLAMA_MODEL = "qwen2.5:7b"
```

Also update the capture filter inside `capture_traffic()`:
```python
"-f", "icmp and dst host 10.0.2.15",   # match DESTINATION_IP above
```

> Replace `10.0.2.15` with whatever `ip a` shows on your own monitoring VM — this value will differ per setup/network mode.

### 7. Verify the model responds before running the full pipeline
Warm up the model (first load is slow) and confirm it returns valid JSON:
```bash
ollama run qwen2.5:7b "Respond only with JSON: {\"test\": \"ok\"}"
```

---

## Running the Pipeline

### On the monitoring VM
```bash
python3 AI_Soc_Analyst.py
```
This starts a capture window (default 100 seconds).

### On the traffic-source VM
While the capture window is active, generate traffic toward the monitoring VM's IP:
```bash
sudo ping -i 0.2 -c 100 <monitoring-VM-IP>
```
This sends ~5 packets/sec for 100 packets — comfortably exceeding the default threshold of 40 within the capture window.

### Output
On success, the monitoring VM's terminal shows the full pipeline output, and two files are generated:
- `alert.json` — the raw detection alert
- `verdict.json` — the alert combined with the AI's triage verdict

Example verdict output:
```json
{
  "verdict": "suspicious",
  "confidence": 75,
  "reasoning": "The high packet count over a short time window suggests potential scanning or noise, which is unusual for normal traffic.",
  "recommended_action": "Further investigate the source and destination of this activity."
}
```

---

## Screenshots

<img width="1920" height="1080" alt="Screenshot 2026-08-09 171559" src="https://github.com/user-attachments/assets/0cd183b7-d3a8-4c15-b302-b9b431dfcc5b" />

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `Permission denied` writing `traffic.pcap` | Running via `sudo -E` changes capture context/permissions | Run the script without `sudo` if your user already has packet-capture capabilities, or run from a writable directory like `/tmp` |
| `EOF` error from `ollama run` | Ollama server crashed, often due to OOM | Check `sudo journalctl -u ollama -f` for `oom-kill`; increase VM RAM to 8 GB+ for `qwen2.5:7b` |
| `HTTPConnectionPool ... Read timed out` | Model still loading (cold start) on CPU-only inference | Warm up the model first with `ollama run qwen2.5:7b "ready"`, and increase the script's `timeout` value (e.g., to 300s) |
| `Destination Host Unreachable` when pinging between VMs | VMs on plain NAT mode, which isolates them from each other | Switch both VMs to **NAT Network** or **Internal Network** |
| `ModuleNotFoundError: No module named 'requests'` | Package not installed in the Python environment being used | `pip install requests --break-system-packages` |

---

## Project Motivation

This project explores how a lightweight, fully local LLM can be integrated into a traditional network-monitoring workflow to automate the first-pass triage step a SOC analyst would normally perform manually — flagging anomalous traffic patterns and providing an initial assessment, freeing up analyst time for deeper investigation. Running entirely offline via Ollama also demonstrates feasibility for air-gapped or highly restricted network environments where cloud AI APIs aren't an option.
