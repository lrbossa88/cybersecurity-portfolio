# Active Directory Attacks and Detection

This is the lab I was building toward the whole time. The last project put one Windows machine into my lab. This one adds a Windows Server 2025 domain controller, joins the Windows 11 box to the domain, and runs the attacks a SOC actually deals with in Active Directory: password spraying, Kerberoasting and AS-REP roasting. Everything reports into Wazuh.

Some of these attacks worked exactly like the textbook. Some got stopped by Server 2025's defaults, which turned out to be a better finding than if they'd just worked. I wrote both down.

Everything was done inside my own home lab, against my own VMs. Lab setup: [Home Lab Setup](../../home-lab/)

## Summary

- Built a domain (`lab.local`) on Windows Server 2025, joined the Windows 11 machine to it, and put a Wazuh agent on the DC
- **Password spray:** one common password against every account found 5 valid logins, including a Domain Admin. In Wazuh it barely registered, the opposite of the loud RDP brute force from my last project
- **Kerberoasting:** the attack ran and the DC logged it (event 4769), but **Server 2025 wouldn't hand out a crackable RC4 ticket**, so the offline crack was blocked by default
- **AS-REP roasting:** correctly found the one account with pre-auth disabled, and hit the same encryption wall
- **Detection gap:** Wazuh logs these Kerberos events but rates them at level 3, the same as a normal login. Nothing says "this looks like an attack"

## Lab and tools

| | |
|---|---|
| Attacker | Kali Linux, 192.168.56.102 |
| Domain controller | Windows Server 2025, DC01, 192.168.56.105, domain lab.local |
| Workstation | Windows 11, WIN11-LAB, 192.168.56.104, joined to lab.local |
| SIEM | Wazuh 4.14.9, 192.168.56.103, agent on the DC |
| Attack tools | NetExec, impacket (GetUserSPNs, GetNPUsers) |

Times are Florida time (UTC-5).

## 1. Building the domain

I installed the AD role on the server and promoted it to a domain controller for a new domain, `lab.local`:

```
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns
```

Then I created a small company: four regular users, a helpdesk account I put in Domain Admins, and two service accounts. The service accounts are set up weak on purpose, because that's exactly how they end up in real environments.

| Account | Set up as | Why |
|---|---|---|
| asmith, bjones, cwhite, dbrown | Regular users, shared password | A normal office where everyone uses the same weak password |
| helpdesk | Domain Admin | An over-privileged account, the kind attackers hunt for |
| svc_sql | Service account with an SPN | Kerberoasting target |
| svc_legacy | Pre-authentication turned off | AS-REP roasting target |

I joined the Windows 11 machine to the domain so the lab is realistic: one server, one workstation, and a normal domain user to log in as. Then I put the Wazuh agent on the DC and turned on Kerberos auditing so service ticket requests get logged:

```
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

<img src="screenshots/01_three_agents_active.png" alt="three agents active" width="800">

All three machines reporting into Wazuh: Ubuntu, Windows 11, and now the domain controller.

## 2. Password spraying

A brute force throws many passwords at one account and locks it out fast. A spray does the opposite: one common password against every account, once each. It stays under the lockout limit and counts on at least one person using a weak password.

From Kali, I sprayed `Passw0rd!` against the whole user list:

```
netexec smb 192.168.56.105 -u users.txt -p 'Passw0rd!' --continue-on-success
```

<img src="screenshots/02_password_spray_kali.png" alt="password spray" width="800">

Five hits, including **helpdesk**, which is a Domain Admin. One weak shared password handed over the keys to the domain. That's not a made-up scenario, it's how a lot of real breaches start.

### What the DC logged

This is the part that matters for a SOC. In Wazuh, the failures:

<img src="screenshots/03_spray_failures_4625.png" alt="spray failures" width="800">

Only **3 failed logons** showed up (event 4625, level 5), and those were just the three accounts whose password wasn't `Passw0rd!`. The five accounts that matched logged a clean success. So from the DC's point of view, five people logged in normally and three typed their password wrong once. Nothing looks like an attack.

The one that should scare you is the success:

<img src="screenshots/04_spray_helpdesk_success.png" alt="helpdesk success" width="800">

**helpdesk**, a Domain Admin, authenticated from Kali and it logged as a normal remote logon (level 6). No burst, no lockout, no high alert.

That's the whole lesson, and it's a sharp contrast with my last project:

| | RDP brute force (last project) | Password spray (this one) |
|---|---|---|
| Pattern | Many passwords, one account | One password, many accounts |
| In the logs | 10 failures in a second | One failure per account |
| Lockout | Yes, account locked | No, stays under the limit |
| Alert | Level 10 | Looks like normal logins |

A brute force screams. A spray whispers. That's why it's the technique that actually works.

## 3. Kerberoasting

In Active Directory, any logged-in user can ask the domain controller for a service account's ticket, and that ticket is encrypted with the service account's password. So you ask as a normal user, take the ticket offline, and try to crack the password without the DC ever seeing you guess.

I requested svc_sql's ticket two ways: from inside the domain as asmith, and from Kali with impacket:

```
impacket-GetUserSPNs lab.local/asmith:'Passw0rd!' -dc-host dc01.lab.local -request -outputfile kerb.txt
```

The request itself worked, and the DC logged **event 4769** for svc_sql every time. But the crack never happened, because of something I didn't expect:

```
KDC_ERR_ETYPE_NOSUPP (KDC has no support for encryption type)
```

**Server 2025 ships with the old RC4 encryption disabled.** The cracking tools request the ticket in RC4 because it's the easiest to crack, and the DC refuses. I tried enabling RC4 on the account and even on the DC's Kerberos service, and the domain still wouldn't issue a weak ticket. In an older domain this attack usually just works and the service account password falls in seconds. Here the default config stopped it.

That's a better result than a successful crack, honestly. It shows that keeping a domain on modern defaults, AES only, takes a whole class of attack off the table. It's also a real thing a defender should check: if someone later turns RC4 back on for a compatibility fix, they've reopened this door.

### What the DC logged

The 4769 events did reach Wazuh:

<img src="screenshots/05_kerberos_events_level3.png" alt="kerberos events at level 3" width="800">

Every single one came in at **level 3**, mapped to generic rules like "Windows Logon Success." A service ticket request for a service account is the exact fingerprint of Kerberoasting, and nothing flagged it. That's the detection gap a custom rule would close: watch for a user requesting service tickets for SPN accounts, especially several in a row, and raise it above the noise.

## 4. AS-REP roasting

This one targets accounts that have Kerberos pre-authentication turned off, a setting that occasionally gets flipped for old software. Those accounts will hand out crackable data to anyone, no password needed at all.

```
impacket-GetNPUsers lab.local/ -usersfile users.txt -no-pass -dc-host dc01.lab.local -format john
```

It correctly picked out **svc_legacy** as the only account missing pre-auth (every other account came back as "doesn't have UF_DONT_REQUIRE_PREAUTH set"). So the attack found its target on its own. Then it hit the same encryption wall as the Kerberoast, so the crackable blob never came out.

Two attacks, same Server 2025 defense. Consistent, and worth knowing.

## Triage notes

### Password spray (the quiet one)

**Who:** 192.168.56.102 (Kali)

**What:** One password tried against 8 accounts. 5 succeeded, including the helpdesk Domain Admin

**When:** 2026-11-03

**Where:** DC01, 192.168.56.105

**MITRE ATT&CK:** T1110.003 Password Spraying, T1078 Valid Accounts

**Severity:** Critical. A Domain Admin account is compromised and the logon looks normal, so it won't jump out in the logs

**What I'd do:** This is the hard part, because there's no single loud alert. I'd look for one source IP authenticating as several different users in a short window, even if each one succeeded. Then force a password reset on helpdesk and every account that matched, check what helpdesk did after logging in, and get everyone off the shared password. Long term, this is why MFA and a ban on common passwords exist. In this case it was my own test.

### Kerberoasting / AS-REP roasting

**Who:** asmith (a normal domain user), from WIN11-LAB

**What:** Requested a service ticket for svc_sql (4769), and requested AS-REP data for svc_legacy

**MITRE ATT&CK:** T1558.003 Kerberoasting, T1558.004 AS-REP Roasting

**Severity:** Medium here, because Server 2025's AES-only setting blocked the crackable part. Would be High on an older domain

**What I'd do:** Confirm the domain still blocks RC4 and that no service account has been switched back to it. Watch for one user requesting service tickets for multiple SPNs quickly. Give service accounts long random passwords, or move them to group managed service accounts so there's nothing worth cracking.

## Issues I ran into

**Kali tools couldn't Kerberoast Server 2025.** Both impacket and NetExec failed with `KDC_ERR_ETYPE_NOSUPP`. The version on my Kali requests RC4 tickets, and Server 2025 disables RC4 by default. I spent a while trying to force RC4 back on, on the account and on the DC, and the domain still wouldn't issue a weak ticket. I decided this was the finding, not a bug to fix: modern AD resists the classic attack out of the box.

**The DC clock was 3 hours behind.** New events were landing in Wazuh stamped 3 hours in the past, so they never showed up in the dashboard's "last 15 minutes." Turned out the server was still on Pacific time while the rest of the lab was on Eastern. Events in the Windows Security log were correct, the dashboard window was just looking in the wrong place. Set-TimeZone fixed it. Good reminder that time sync is not optional in a SIEM, and that a quiet dashboard doesn't always mean nothing happened.

## Lessons learned

- **The quiet attack is the dangerous one.** The spray compromised a Domain Admin and looked like a normal login, while last project's noisy brute force got caught instantly
- **Modern defaults matter.** Server 2025 blocking RC4 shut down two classic attacks with no work from me. The flip side is that one compatibility change could reopen them
- **A SIEM logging an event isn't the same as detecting it.** The Kerberoast events were right there in Wazuh at level 3, indistinguishable from normal traffic, until someone writes a rule that knows what the pattern means
- **Check the clock.** A time skew made it look like Wazuh was broken when it was working fine

## Limitations

- Everything ran from one attacker against a small, quiet domain. A real one has thousands of logons an hour, which is exactly what makes a spray so easy to hide in
- Because Server 2025 blocked the roasting cracks, I didn't get to show the full chain of cracking a service account and reusing it. I'd need to deliberately weaken the domain's encryption settings to demo that, which I may do in a follow-up
- I focused on the attacks and the logging. I didn't finish writing and testing the custom detection rules, which is the natural next step

## What I'd do next

- Write and test a Wazuh rule for password spraying: one source, many target accounts, short time window
- Write a rule for a user requesting several service tickets quickly (the Kerberoasting pattern)
- Set up a second domain-joined machine so I can show lateral movement, logging in to one box with creds stolen from another
- Turn on Wazuh active response so a confirmed attack can disable an account or block an IP on its own
