# silent-tripwires-mvp

**Silent Tripwires** is a lean, solo defensive-security study that measures (1) how quickly fresh cloud IPs are found and (2) **bounceback/response-sensitivity** — how scanners change behavior when a host replies vs stays silent: **DROP** everything, **REJECT** with RST/ICMP, or **DECOY** on SSH.  
Over ~14 days we capture packets (`dumpcap`/`tshark`) and compute **TTFA**, **bounceback rates** after RST/ICMP or a decoy banner, handshake completion on 22/tcp, retry within 60s, revisit within 1–7 days, and Top-N ports — no SIEM required.  
The design is **safety-first** (egress default-deny, no amplification) and fully reproducible with a tiny Python/pandas analysis.

---

**Key metrics**
- **TTFA** – time from VM go-live to first malicious hit
- **Bounceback rate** – % of sources that send a follow-up packet after our **REJECT** (RST/ICMP) or **DECOY** banner, incl. retry count within 60s
- **SSH handshake completion** – % of 22/tcp attempts that finish the TCP handshake
- **Revisit** – % of sources that return within 1–7 days
- **Top-N ports / ASNs** – rank by unique sources and hits

---

## Sensors (MVP)

### Sensor A — DROP + PCAP (background-noise baseline)
- **Role:** Quiet listener. Drops unsolicited traffic so we can measure “background radiation” without replying.  
- **Host:** Ubuntu 22.04 LTS, Standard B1ms (West US 2).  
- **Network policy (iptables):**
  - ACCEPT `lo`, ACCEPT `ESTABLISHED,RELATED`
  - **ACCEPT TCP/22 from admin IP (69.161.55.100)**
  - **Policy DROP** for everything else (no replies)
- **Capture:** `dumpcap` ring buffer → `/var/log/pcap/capture_*.pcapng`  
  (1-hour files, keep ~336 files ≈ ~2 weeks)
- **Service:** `packet-capture.service` (enabled & running)
- **Status:** Deployed, capturing; inbound denied except admin SSH.

---

### Sensor B — DECOY (Cowrie SSH honeypot) + PCAP
- **Role:** Lures scanners/brute-forcers; yields high-signal transcripts/credentials.  
- **Host:** Ubuntu 22.04 LTS, Standard B1ms (West US 2).  
- **Honeypot:** Docker image `cowrie/cowrie:latest` bound to **TCP/22** (public).  
- **Logs:**
  - Text log persisted to **`/var/log/cowrie/cowrie.log`** via a systemd follower (`cowrie-logfile.service`) that tails container stdout.
  - `tty/` session files and JSON can be added later if needed.
- **Network policy (iptables):**
  - ACCEPT `lo`, ACCEPT `ESTABLISHED,RELATED`
  - **ACCEPT TCP/22 from anywhere** (for the decoy)
  - Default deny for other inbound
- **Capture:** Same `dumpcap` ring buffer as A → `/var/log/pcap/`
- **Status:** Deployed, Cowrie is accepting connections and generating logs; follower service is enabled & writing to disk.

---

### Sensor C — REJECT + PCAP (active-control baseline)
- **Role:** Same exposure as A, but **actively rejects** (TCP RST / ICMP) instead of silently dropping — lets us contrast scanner behavior when a host “talks back.”  
- **Host:** Ubuntu 22.04 LTS, Standard B1ms (West US 2).  
- **Network policy (iptables):**
  - ACCEPT `lo`, ACCEPT `ESTABLISHED,RELATED`
  - **ACCEPT TCP/22 from admin IP (69.161.55.100)**
  - **REJECT all other TCP** (with TCP RST)
  - **REJECT all UDP** (ICMP port unreachable)
  - **Policy DROP**
- **Capture:** `dumpcap` ring buffer → `/var/log/pcap/`
- **Service:** `packet-capture.service` (enabled & running)
- **Status:** Deployed, packet capture active; first pcap file created.

---

## Common setup notes
- All sensors: **Ubuntu 22.04 LTS (x64), West US 2**.  
- Packet capture standardized via `dumpcap` ring buffer (1-hour rotation, ~2 weeks retention).  
- Management primarily through Azure Portal **Run Command**.  
- SSH admin is allowed from **69.161.55.100** on **A** and **C** (B is managed via portal; the decoy owns port 22).

---

## Quick verification
```bash
# Packet capture running?
systemctl is-active packet-capture && echo "pcap: active"

# Recent pcaps
ls -lh /var/log/pcap | tail

# (Sensor B only) Honeypot log
[ -f /var/log/cowrie/cowrie.log ] && tail -n 40 /var/log/cowrie/cowrie.log


