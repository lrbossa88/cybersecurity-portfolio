# Cybersecurity Portfolio | Lucas Ribeiro Bossa

I'm working toward a SOC Analyst Tier 1 role. This portfolio has my home lab projects, where I attack and defend my own VMs and document it like a real investigation, plus my coursework from the Google Cybersecurity Certificate.

The lab projects build on each other: I found an SSH brute force in the logs, then looked at it in the packets, then set up a SIEM to catch it automatically and wrote a custom rule for what the SIEM missed. The SIEM couldn't see the port scan, so I added a network IDS and wrote a second rule so its most serious alerts don't get buried. Then I added a Windows 11 machine with Sysmon, attacked it over RDP and planted a backdoor admin account. The last one builds a full Active Directory domain and runs the attacks a SOC sees in AD: password spraying, Kerberoasting and AS-REP roasting.

## Home Lab Projects

| Project | What I did | Skills |
|---|---|---|
| [Active Directory Attacks and Detection](projects/active-directory-attacks/) | Built a Windows Server 2025 domain, joined the Windows 11 box to it, and ran password spraying, Kerberoasting and AS-REP roasting. Sprayed a Domain Admin that looked like a normal login in the SIEM, and found Server 2025 blocks RC4 roasting by default | Active Directory, Windows Server, password spraying, Kerberoasting, domain security, MITRE ATT&CK |
| [Windows Endpoint Detection with Sysmon and Wazuh](projects/windows-sysmon-detection/) | Added a Windows 11 machine with Sysmon feeding Wazuh. Brute forced RDP, then created a backdoor admin account and ran encoded PowerShell. The backdoor only raised a level 8 while a harmless PowerShell file raised a level 15, so I **wrote a correlation rule** for the backdoor and **tuned out the false positive** | Windows Event Logs, Sysmon, Wazuh, custom detection rules, alert tuning, MITRE ATT&CK |
| [Network IDS with Suricata: Catching What the SIEM Missed](projects/suricata-ids-detection/) | Added Suricata to the lab, caught the port scan Wazuh missed and flagged the brute force 5.7 seconds before fail2ban blocked it. Sent its alerts to Wazuh, found they all came in at level 3, and **wrote a custom rule** that raises Suricata's highest severity to level 12 | Suricata, network IDS, Wazuh, custom detection rules, MITRE ATT&CK |
| [SIEM Detection with Wazuh: Finding and Fixing a Detection Gap](projects/wazuh-siem-detection/) | Connected Ubuntu to a Wazuh SIEM and re-ran my attacks. Found that a successful login after failed attempts only raised a level 3 alert, so I **wrote a custom Wazuh rule** that raises a level 12 and tested it | Wazuh, SIEM alert triage, custom detection rules, MITRE ATT&CK |
| [Network Traffic Investigation: Port Scan and Brute Force on the Wire](projects/network-traffic-investigation/) | Captured a port scan and an SSH brute force with tcpdump, analyzed them in Wireshark, found nmap's packet fingerprint and caught the fail2ban block in the packets | Packet analysis, tcpdump, Wireshark, nmap, MITRE ATT&CK |
| [Linux SSH Attack Detection and Defensive Validation](projects/ssh-attack-detection/) | Ran a controlled SSH brute force with Hydra, found it in the logs, triaged it, set up fail2ban and re-tested to prove it blocked the attack | Log analysis, triage, MITRE ATT&CK, fail2ban, Linux hardening |
| [Home Lab Setup](home-lab/) | Built a five VM lab in VirtualBox (Kali, Ubuntu, Windows 11, a Windows Server 2025 domain controller, and a Wazuh SIEM) with NAT and host-only networking. All my lab projects run on this | Virtualization, networking, Active Directory, troubleshooting |

## Coursework

From the Google Cybersecurity Certificate. These are course labs, not real incidents.

| Write-up | What it covers |
|---|---|
| [Incident Response Documentation](coursework/incident-response-documentation/) | Incident handler's journal (ransomware, phishing file hash in VirusTotal) and a data leak review against NIST SP 800-53 AC-6 |
| [SQL Security Investigations](coursework/sql-security-investigations/) | Filtering login attempts (after hours, specific dates, by country) and joining employees, machines and login data |
| [Linux User and Permission Management](coursework/linux-user-and-permission-management/) | Adding, modifying and removing users, file ownership, and fixing file and directory permissions |
| [Python Allow List Automation](coursework/python-allow-list-automation/) | Script that removes revoked IPs from an allow list file |

## Skills and Tools

- **SIEM:** Wazuh (alert triage, custom detection rules, alert tuning)
- **IDS:** Suricata (ET Open rules, eve.json, tuning HOME_NET)
- **Security tools:** Sysmon, Wireshark, tcpdump, nmap, Hydra, NetExec, impacket, fail2ban, VirusTotal
- **Log and traffic analysis:** Windows Event Logs (4625, 4720, 4732, 4740, 4768, 4769), Sysmon events, Active Directory logons, journalctl, Linux auth logs, fail2ban logs, packet captures (pcap)
- **Systems:** Kali Linux, Ubuntu, Windows 11, Windows Server 2025, Active Directory, Amazon Linux, Oracle VirtualBox
- **Languages:** SQL, Python, Bash, PowerShell, Wazuh rule XML
- **Frameworks:** MITRE ATT&CK, NIST CSF, NIST SP 800-53

## Certifications

- Google Cybersecurity Professional Certificate (Completed)
- Palo Alto Networks Cortex Foundations (Completed)
- CompTIA Security+ SY0-701 (In progress)

More details: [certifications](certifications/)

## Project Tracker

**In progress**
- Nothing right now, next lab project coming soon

**Completed**
- Active Directory Attacks and Detection
- Windows Endpoint Detection with Sysmon and Wazuh
- Network IDS with Suricata: Catching What the SIEM Missed
- SIEM Detection with Wazuh: Finding and Fixing a Detection Gap
- Network Traffic Investigation: Port Scan and Brute Force on the Wire
- Linux SSH Attack Detection and Defensive Validation
- Home Lab Setup
- Google Cybersecurity Certificate coursework

**Planned**
- Write and test custom Wazuh rules for password spraying and Kerberoasting
- Add a firewall to the home lab

## Contact

- Email: lrbossa88@gmail.com
- LinkedIn: [linkedin.com/in/lrbossa88](https://www.linkedin.com/in/lrbossa88)
