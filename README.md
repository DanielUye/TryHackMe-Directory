# TryHackMe: Directory — Digital Forensics & Network Packet Analysis Report
[![Target: TryHackMe](https://img.shields.io/badge/Platform-TryHackMe-red?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com/room/directory)
[![Target OS: Windows](https://img.shields.io/badge/Target%20OS-Windows%20(Active%20Directory)-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#)
[![Difficulty: Hard](https://img.shields.io/badge/Difficulty-Hard-orange?style=for-the-badge)](#)
[![Category: DFIR / Network Forensics](https://img.shields.io/badge/Category-Network%20Forensics%20%2F%20DFIR-blueviolet?style=for-the-badge&logo=wireshark&logoColor=white)](#)
## Executive Summary
An incident response engagement was conducted for a small music production company following the discovery of an extortion/ransom note on the desktop of Larry (Art Director). Due to early-stage infrastructure maturity, endpoint detection and centralized logging were absent; however, an active network tap captured raw traffic (traffic.pcap) encompassing the entire adversary lifecycle.This report details the end-to-end digital forensic analysis of the network capture: from port scanning and Kerberos pre-authentication abuse (AS-REP Roasting) to WinRM traffic decryption and post-exploitation command extraction.
## Incident & Engagement Metadata

| Metric | Engagement Details |
| :--- | :--- |
| **Target Machine** | `Directory` (TryHackMe) |
| **Target IP** | `10.10.x.x` *(Extracted from `traffic.pcap`)* |
| **Operating System** | Windows Server (Active Directory Domain Controller) |
| **Initial Foothold** | Port Reconnaissance $\rightarrow$ AS-REP Roasting (`DIRECTORY.THM\larry`) $\rightarrow$ Password Recovery |
| **Lateral Movement / Access** | WinRM (Port 5985 `/wsman`) Authentication via Recovered Credentials |
| **Post-Exploitation / Actions** | Decrypted PowerShell Session $\rightarrow$ Domain Enumeration & Extortion Note Deployment |
| **Impact Rating** | **CRITICAL** (Full Domain Credential Compromise & Arbitrary Remote Execution) |

---

## Attack Lifecycle Breakdown

| Phase | Vector / Technique | Protocol & Port | Tooling & Mechanism | Key Outcome / Finding |
| :--- | :--- | :--- | :--- | :--- |
| **1. Reconnaissance** | TCP SYN Port Scan | `TCP` (Multiple) | Wireshark, TShark (`SYN=1, ACK=1`) | Identified 14 open ports (53, 88, 135, 389, 445, 5985, etc.) |
| **2. Enumeration** | AS-REP Roasting | `Kerberos` (Port 88) | `Krb5RoastParser` | Extracted `krb5asrep` hash for user `DIRECTORY.THM\larry` |
| **3. Offline Cracking** | Dictionary Attack | N/A (Offline) | John the Ripper (`rockyou.txt`) | Recovered plaintext password for `larry` |
| **4. Initial Access** | WinRM Remote Session | `HTTP / WS-Man` (Port 5985) | WinRM Decryption Script (`pyshark`) | Decrypted encrypted SPNEGO/Kerberos session payloads |
| **5. Post-Exploitation** | Host & Domain Triage | `PowerShell` via WinRM | XML & Base64 Payload Parser | Extracted executed commands (`whoami`, `net user`, `net group`) and dropped note |


## Attack Lifecycle Overview

---
[ TCP PORT SCAN ] ──────► [ AS-REP ROASTING ] ──────► [ HASH CRACKING ] ──────► [ DECRYPT WINRM ]
 Port Reconnaissance       Kerberos AS-REQ / AS-REP     Offline Brute-Force       Decrypted WS-Man / PowerShell
 Ports: 53, 88, 135, ...   Extracted krb5asrep Hash     Password Recovery         Extracted Executed Commands
-----

## Investigation & Technical Walkthrough
### Phase 1: Network Reconnaissance & Open Port Discovery
### Objective: Identify the open ports discovered by the threat actor during initial scanning.

### 1. Conversation & Traffic Volume Analysis

To isolate the attacker and target IP addresses:

1. Open `traffic.pcap` in **Wireshark**.
2. Navigate to **Statistics** $\rightarrow$ **Conversations** $\rightarrow$ **IPv4**.
3. Sort by **Total Packets / Bytes** to locate the dominant conversation between the external attacker IP and the internal domain controller/host.

### 2. Filtering for Successful TCP Handshakes
When an attacker performs a TCP SYN port scan (e.g., nmap -sS), open ports respond with a TCP SYN-ACK packet (SYN=1, ACK=1), whereas closed ports respond with a RST-ACK.

Apply the following display filter in Wireshark:
```bash
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

(Alternatively, filter by the uniform frame length characteristic of these scan responses: frame.len == 58)

#### Filter & Scan Dissection:

* `tcp.flags.syn == 1 && tcp.flags.ack == 1` — Isolates servers acknowledging probe packets, confirming active listening services.
* `frame.len == 58` — Restricts display to standard TCP SYN-ACK handshake packets without payload data.

> **Next Step:** Inspect the **Source Port** column of the matching packets sent from the target machine back to the attacker to identify open services.

## Task 1 Answer:
Open Ports (Ascending Order):
```text
53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389
```

### Phase 2: Active Directory Enumeration & AS-REP Roasting
### Objective: 
### Identify the target user compromised via Kerberos pre-authentication failure and extract the associated hash.

#### 1. Protocol Hierarchy Analysis
1. Navigate to **Statistics** $\rightarrow$ **Protocol Hierarchy**.
2. Identify the prominent **Kerberos** traffic breakdown, observing the volume of `AS-REQ` and `AS-REP` messages.
3. **Vulnerability Mechanism:** When Active Directory accounts are configured with the `DONT_REQ_PREAUTH` (*Do not require Kerberos pre-authentication*) attribute, an attacker can submit an `AS-REQ` for that username without providing proof of authentication. The Key Distribution Center (KDC) responds with an `AS-REP` containing data encrypted with the user's password hash, exposing it to offline dictionary and brute-force attacks (AS-REP Roasting).

#### 2. Extracting Kerberos AS-REP Hashes
Clone and run Krb5RoastParser to parse the PCAP file and extract AS-REP roasted hashes:
```bash
# Clone the parser utility
git clone https://github.com/jalvarezz13/Krb5RoastParser.git
cd Krb5RoastParser

# Extract AS-REP hashes from the network capture
python3 krb5_roast_parser.py ../traffic.pcap as_rep
```

#### Output:
The tool enumerates Kerberos pre-authentication requests, identifying valid accounts and outputting roastable hashes formatted for Hashcat/John the Ripper.


## Task 2 Answer:
```text
DIRECTORY.THM\larry
```

### Phase 3: Hash Extraction & Analysis
### Objective: 
### Isolate the last 30 characters of the recovered hash string.
Save the extracted Kerberos hash string for user **larry** into a file named **hash.txt** and clean any trailing whitespace:
```bash
# Verify the hash content
cat hash.txt

# Extract the exact last 30 characters
tail -c 30 hash.txt
```

## Task 3 Answer:
```text
[LAST_30_CHARACTERS_OF_LARRY_HASH]
```

### Phase 4: Offline Credential Recovery (Hash Cracking)
### Objective: 
### Recover the plaintext password for the compromised account.
Option A: John the Ripper **(Recommended for CPU efficiency)**
```bash
# Crack the krb5asrep hash using the rockyou dictionary
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Display the recovered plaintext password
john --format=krb5asrep --show hash.txt
```

Option B: Hashcat **(GPU Acceleration)**
```bash
# Hashcat mode 18200: Kerberos 5 AS-REP etype 23
hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

## Task 4 Answer:
### Plaintext Password:
```text
[RECOVERED_PLAINTEXT_PASSWORD]
```

### Phase 5: WinRM Traffic Decryption & Post-Exploitation Forensics

#### Objective: Decrypt encrypted Windows Remote Management (WinRM) sessions to reconstruct the threat actor's command history.

#### 1. Identifying the Administrative Channel
In Wireshark, apply an HTTP filter:

```wireshark
http.request.method == "POST"
```

* **Observation:** The attacker initiated multiple POST requests to the `/wsman` endpoint over port `5985` (WinRM).
* Following the HTTP Stream reveals Base64-encoded, encrypted SPNEGO/Kerberos payload wrappers. Standard Wireshark cannot natively decrypt WinRM encrypted streams without session key derivation.

---

#### 2. Environment & Tooling Setup
To decrypt the WinRM session using the recovered password, configure the Python decryption environment:

```bash
# Install system dependencies
sudo apt update && sudo apt install -y python3 python3-pip tshark

# Install Python dissection libraries
python3 -m pip install pyshark cryptography argcomplete --break-system-packages
```

Create the custom decryption script:

```bash
# Create local script file
nano winrm_decrypt.py
```

*(Paste the script source from the Jordan Borean WinRM Decryptor Gist)*

```bash
chmod +x winrm_decrypt.py
```

---

#### 3. Decrypting WinRM Network Payloads

Execute the decryption script by supplying the recovered password and targeting the PCAP:

```bash
# Decrypt all WinRM streams to a text file
python3 winrm_decrypt.py -p '<RECOVERED_PASSWORD>' ../traffic.pcap > decrypted_traffic.txt
```

---

#### 4. Automated Extraction & Decoding Pipeline

WinRM command arguments are encapsulated in XML structures inside `<rsp:Arguments>` tags as Base64-encoded strings.

```bash
# Step 1: Extract all Base64 argument strings from XML nodes
grep -oP '(?<=<rsp:Arguments>).*?(?=</rsp:Arguments>)' decrypted_traffic.txt > encoded_arguments.txt

# Step 2: Loop through and decode each argument block
while read -r line; do
  echo "$line" | base64 --decode >> arguments.txt
  echo "" >> arguments.txt
done < encoded_arguments.txt

# Step 3: Parse distinct PowerShell/Command string values
grep -a '<S N="V">' arguments.txt | awk -F'[<>]' '{print $3}'
```

---

#### 5. Threat Actor Command Execution Log

Reviewing the decoded output reveals the exact command sequence executed by the adversary:

```powershell
# Command 1: Privilege & Security Identifier (SID) Enumeration
whoami /all

# Command 2: Credential Access — Dumping Registry Hives
reg save HKLM\SYSTEM C:\SYSTEM
reg save HKLM\SAM C:\SAM
reg save HKLM\SECURITY C:\SECURITY

# Command 3: Integrity Check (Validating Dump File Sizes)
(get-item 'C:\SAM').length
(get-item 'C:\SYSTEM').length

# Command 4: Directory Navigation to Target User Desktop
cd ..\Desktop\

# Command 5: Extortion Note Creation & Flag Drop
echo "THM{Ya_G0t_R0aSt3d!}" > note.txt
```

---

#### Task 5 Answers:

* **Second and Third Commands Executed:**
  ```text
  reg save HKLM\SYSTEM C:\SYSTEM,reg save HKLM\SAM C:\SAM
  ```

* **Extortion Note / Flag Recovered:**
  ```text
  THM{Ya_G0t_R0aSt3d!}
  ```

---

## Forensic Findings & Mitigation Blueprint

| Finding | Root Cause | Hardening & Remediation |
| :--- | :--- | :--- |
| **Exposed Port Surface** | Broad network accessibility on domain controllers / core systems. | Implement host-level firewalls and network segmentation to restrict WinRM (`5985`), RPC, and SMB to dedicated management subnets. |
| **AS-REP Roasting** | Account configured with `Do not require Kerberos preauthentication` enabled. | Audit Active Directory using `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}` and ensure Kerberos pre-authentication is enforced across all domain accounts. |
| **Weak Password Complexity** | Account password was present in standard dictionary wordlists (`rockyou.txt`). | Enforce strong passphrase requirements (minimum 15+ characters) and deploy Fine-Grained Password Policies (FGPP) with lockout thresholds. |
| **Unrestricted Remote Management** | Direct WinRM access allowed arbitrary command execution without MFA or JEA. | Restrict WinRM listeners using Just Enough Administration (JEA), enforce network-level authentication, and require Jump Boxes / Privileged Access Management (PAM). |
