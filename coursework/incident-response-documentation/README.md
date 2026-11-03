# Incident Response Documentation

*Google Cybersecurity Certificate coursework*

Documentation exercises from the course: an incident handler's journal for logging incidents as they're investigated, and a worksheet reviewing a data leak against NIST SP 800-53.

**Frameworks:** NIST Incident Response Lifecycle, NIST SP 800-53 (AC-6 Least Privilege)

**Tools:** VirusTotal, Wireshark, tcpdump

## Incident handler's journal

### Entry 1: Ransomware at a health care clinic

**Date:** July 23, 2024

**Tools used:** None

**Scenario:** A small U.S. health care clinic had a ransomware attack on a Tuesday morning around 9:00 a.m. Employees couldn't open medical records or the software they needed, and a ransom note showed up on their screens. The attackers got in through targeted phishing emails with a malicious attachment that installed malware once it was downloaded. The clinic had to shut down its systems and reach out to other organizations for help.

**Lifecycle phases:**
1. **Detection and Analysis:** The clinic found out when employees couldn't access files and saw the ransom note. They contacted outside organizations for technical help with the analysis.
2. **Containment, Eradication and Recovery:** They shut down their computer systems to contain it. Since they couldn't recover on their own, they brought in outside help.

**The 5 W's**
- **Who:** An organized group of unethical hackers known for targeting healthcare and transportation
- **What:** Ransomware incident, critical files encrypted
- **When:** Tuesday, 9:00 a.m.
- **Where:** Small U.S. health care clinic
- **Why:** The phishing emails worked. Once inside, the attackers deployed ransomware to encrypt files. The motive looks financial since they're asking for money for the decryption key.

**Notes:**
- How could they prevent this again? Phishing awareness training for staff, since that's how the attackers got in.
- Should they pay the ransom? No. Sometimes ransomware is just a bluff to get money and the key never comes. They should restore from their latest backup.

### Entry 2: Suspicious file hash

**Date:** July 27, 2024

**Tools used:** VirusTotal

**Scenario:** An employee received a phishing email with a malicious attachment, downloaded it and ran it. The IDS picked it up and sent an alert to the SOC. I checked the file's hash in VirusTotal to confirm it was malicious.

**The 5 W's**
- **Who:** Unknown malicious actor
- **What:** Phishing email with a malicious file that was downloaded and executed
- **When:** 1:20 p.m., when the IDS alert came into the SOC
- **Where:** An employee's computer at a financial services company
- **Why:** The employee downloaded and ran the attachment

**Notes:** The company should improve security awareness training so employees can spot phishing emails before opening attachments.

Other journal entries from the course were tool practice with no incident to document: analyzing a packet capture in Wireshark and capturing packets with tcpdump.

## Data leak worksheet

**Incident summary:** A sales manager shared a folder of internal-only documents with their team during a meeting. It had files about an unannounced product, customer analytics and promotional materials. After the meeting the manager didn't remove access to the folder, just told the team to wait for approval before sharing the promo materials.

Later, on a video call with a business partner, a sales rep meant to share the link to the promotional materials but shared the link to the whole internal folder by accident. The business partner then posted the link on their company's social media, thinking it was the promo materials.

| | |
|---|---|
| **Control** | Least privilege |
| **Issues** | Access to the internal folder wasn't limited to the people who needed it, and it was never removed after the meeting. Nothing stopped the link from being shared with someone outside the company. |
| **Review** | NIST SP 800-53 AC-6 covers least privilege: users should only have the access they need to do their job. It also suggests control enhancements to make least privilege more effective. |
| **Recommendations** | 1. Restrict access based on role. 2. Regular audits to make sure users have the right level of access. |
| **Justification** | Making sure only the right team has access to the right data is the whole point of least privilege. If access had been limited and removed after the meeting, the sales rep wouldn't have had the internal link to share. Regular audits make sure access gets cleaned up and only current employees who need it keep it. |
