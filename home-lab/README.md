# Home Lab Setup

This is the home lab I use for my security projects. It runs on my Windows laptop in Oracle VirtualBox. Right now it's five VMs: Kali Linux as the attacker, Ubuntu and Windows 11 as targets, a Windows Server 2025 domain controller, and a Wazuh SIEM server watching all of them. I plan on adding more to it over time.

Every project in this portfolio runs on this lab and links back here so I don't have to repeat the setup every time.

## What's in the lab

| Machine | OS | Role | Lab IP (host-only) | NAT IP |
|---|---|---|---|---|
| Kali | Kali Linux | Attacker / testing machine | 192.168.56.102 | 10.0.2.15 |
| Ubuntu | Ubuntu 26.04.1 LTS | Target, monitored by Wazuh | 192.168.56.101 | 10.0.2.15 |
| Windows 11 | Windows 11 Enterprise (evaluation) | Target and domain workstation, monitored by Wazuh and Sysmon | 192.168.56.104 | 10.0.2.15 |
| DC01 | Windows Server 2025 (evaluation) | Domain controller for lab.local, monitored by Wazuh | 192.168.56.105 | 10.0.2.15 |
| Wazuh | Amazon Linux 2023 (Wazuh 4.14.9 OVA) | SIEM server | 192.168.56.103 | 10.0.2.15 |
| Windows host | Windows | Admin access (SSH into the VMs, Wazuh dashboard in the browser) | 192.168.56.1 | N/A |

## Network setup

Each VM has two network adapters:

- **NAT:** gives the VM internet through the host so I can install updates and tools. VirtualBox gives each VM its own separate NAT, which is why they all show 10.0.2.15. They can't see each other on this network.
- **Host-only:** a private network between the VMs and my host. This is the lab network and all testing happens over it.

Keeping the testing on host-only means any attack traffic stays inside the lab and never touches my home network. Nothing outside my laptop can reach any of the VMs.

```
                       Windows host (192.168.56.1)
                                    |
        ------------------------- host-only network 192.168.56.0/24 -------------------------
      |               |                  |                  |                 |
  Kali          Ubuntu          Windows 11         DC01 (Server)      Wazuh (SIEM)
  attacker      target          workstation        lab.local DC       manager + dashboard
  .102          .101            .104               .105               .103
       the three Wazuh agents send logs ------------------------------> Wazuh
```

## What's set up on each machine

This is the current state of the lab. Each item links to the project where I set it up.

**Kali (attacker)**
- nmap, Hydra, NetExec, Wireshark, tcpdump (all come with Kali)
- A 20 password wordlist for the brute force tests, with the real password left out on purpose

**Ubuntu (target)**
- OpenSSH server on port 22, password logins allowed so there's something to attack
- `labuser1`, a regular test account with no sudo, so all test activity is tied to one user and my real admin account never gets locked out
- fail2ban: bans an IP after 5 failed SSH logins in 10 minutes for 10 minutes, my Windows host is excluded so I can't lock myself out ([SSH project](../projects/ssh-attack-detection/))
- tcpdump for packet captures ([network project](../projects/network-traffic-investigation/))
- Suricata 8.0.3 network IDS with the ET Open rules, listening on enp0s8, alerts sent to Wazuh ([Suricata project](../projects/suricata-ids-detection/))
- Wazuh agent `ubuntu-target`, sending the system journal and Suricata alerts to the Wazuh server ([Wazuh project](../projects/wazuh-siem-detection/))

**Windows 11 (target)**
- Static IP 192.168.56.104, computer name WIN11-LAB
- RDP turned on, with `labuser2`, a regular test account for the brute force tests
- Joined to the lab.local domain as a workstation ([AD project](../projects/active-directory-attacks/))
- Windows' default lockout policy: 10 bad passwords locks the account
- Sysmon v15.22 with the SwiftOnSecurity config ([Windows project](../projects/windows-sysmon-detection/))
- Wazuh agent `win11-lab`, sending the Windows Security log and Sysmon events to the Wazuh server ([Windows project](../projects/windows-sysmon-detection/))

**DC01 (domain controller)**
- Windows Server 2025, computer name DC01, static IP 192.168.56.105, DNS pointed at itself
- Domain controller for `lab.local`, with DNS and the AD role
- A few domain users, a Domain Admin helpdesk account, and two deliberately weak service accounts for Kerberoasting and AS-REP roasting ([AD project](../projects/active-directory-attacks/))
- Kerberos auditing turned on so service ticket requests (event 4769) get logged
- Wazuh agent `dc01`, sending the Windows Security log to the Wazuh server ([AD project](../projects/active-directory-attacks/))

**Wazuh (SIEM)**
- Wazuh manager, indexer and dashboard 4.14.9, dashboard at `https://192.168.56.103`
- Default passwords changed
- Custom rule **100100**: level 12 alert for a successful SSH login after failed attempts from the same IP ([Wazuh project](../projects/wazuh-siem-detection/))
- Custom rule **100200**: raises Suricata's highest severity alerts to level 12 ([Suricata project](../projects/suricata-ids-detection/))
- Custom rule **100300**: level 14 alert for a new local account added to Administrators within 5 minutes, and **100301** tunes a PowerShell false positive down from level 15 to 3 ([Windows project](../projects/windows-sysmon-detection/))
- Custom rule **100400**: level 12 alert for password spraying, one source IP failing logon against several different accounts in a short window ([AD project](../projects/active-directory-attacks/))

## Building it

### Kali and Ubuntu

Both VMs got a NAT adapter and a host-only adapter on the same VirtualBox Host-Only Ethernet Adapter.

<img src="network/01_kali_adapter1_nat.png" alt="Kali adapter 1 NAT" width="800">

<img src="network/02_kali_adapter2_hostonly.png" alt="Kali adapter 2 host-only" width="800">
<img src="network/03_ubuntu_adapter1_nat.png" alt="Ubuntu adapter 1 NAT" width="800">

<img src="network/04_ubuntu_adapter2_hostonly.png" alt="Ubuntu adapter 2 host-only" width="800">

Both VMs are on the same host-only adapter, that's what lets them talk to each other.

Kali, both adapters up on their own profiles (`nat` and `hostonly`):

<img src="network/05_kali_ip.png" alt="Kali IP and nmcli status" width="800">

Ubuntu:

<img src="network/06_ubuntu_ip.png" alt="Ubuntu IP" width="800">

Ping from Kali to Ubuntu over the host-only network. 4 sent, 4 received, 0% packet loss:

<img src="network/07_ping_kali_to_ubuntu.png" alt="Ping Kali to Ubuntu" width="800">

### Wazuh

For the SIEM I used the official Wazuh 4.14.9 OVA, which comes with the manager, indexer and dashboard already installed, and imported it into VirtualBox (4 CPUs, 8 GB RAM). Same network setup as the other VMs. The dashboard is at `https://192.168.56.103`, only reachable from my host and the lab VMs.

<img src="wazuh/01_wazuh_ip.png" alt="Wazuh IP" width="800">

I installed the Wazuh agent on Ubuntu using the command the dashboard generates, pointed at the Wazuh server:

<img src="wazuh/02_wazuh_agent_install.png" alt="Agent install" width="800">

Ubuntu showing up as an active agent:

<img src="wazuh/03_wazuh_agent_active.png" alt="Agent active" width="800">

### Windows 11

I used the free 90 day Windows 11 Enterprise evaluation from Microsoft, with 8 GB RAM and 2 CPUs. Same NAT and host-only adapters as the other VMs, and a static IP of 192.168.56.104 set with `New-NetIPAddress`. Sysmon and the Wazuh agent setup are in the [Windows project](../projects/windows-sysmon-detection/).

## Issues I ran into

**Kali would only keep one adapter up at a time.** After setup, Kali's NAT adapter (eth0) had no IP so there was no internet. `dhclient` isn't on newer Kali anymore, so I used `nmcli device connect eth0`. That fixed eth0 but then eth1 lost its IP. Turns out Kali only had one connection profile ("Wired connection 1") and NetworkManager kept moving it back and forth between the two adapters. I fixed it by making a separate profile for each adapter, tied to the interface name:

```
sudo nmcli connection add type ethernet ifname eth0 con-name nat
sudo nmcli connection add type ethernet ifname eth1 con-name hostonly
sudo nmcli connection delete "Wired connection 1"
sudo nmcli connection up nat
sudo nmcli connection up hostonly
```

After that both adapters stayed connected on their own profiles.

**Copy/paste didn't work in the Ubuntu or Wazuh VM windows.** Ubuntu 26.04 only runs on Wayland and VirtualBox's shared clipboard doesn't play well with it, and the Wazuh VM is text only. My workaround was to SSH into both from PowerShell on my Windows host over the host-only network, then copy/paste works normally. Those admin logins show up in the logs from 192.168.56.1, so they're easy to tell apart from Kali's test traffic coming from .102.

**Wazuh's second adapter was on Bridged instead of NAT.** `ip -br a` showed a 192.168.4.x address, which is my home network, not VirtualBox NAT (10.0.2.x). That meant the Wazuh dashboard, still on the default `admin/admin` login, could be reached by anything on my Wi-Fi. Switched the adapter to NAT and it came back with 10.0.2.15.

**Wazuh default passwords.** Every copy of the OVA ships with the same logins and they're printed right on the console screen. I changed the VM login with `passwd` and the dashboard `admin` password with Wazuh's password tool, then checked Filebeat could still connect with `sudo filebeat test output`.

**The Windows 11 install sat on a black screen.** VirtualBox showed a green turtle icon, which means Hyper-V was running on my laptop underneath VirtualBox and slowing every VM down. I had to turn off Memory integrity, virtualization-based security, the Virtual Machine Platform feature and `hypervisorlaunchtype` before VirtualBox got full speed back. Full details in the [Windows project](../projects/windows-sysmon-detection/).
