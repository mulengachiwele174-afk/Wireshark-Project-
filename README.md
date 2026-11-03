<h1 align="center">Wireshark Network Forensics Labs</h1>

<p align="center">
  <b>Hands-on packet analysis investigations in a simulated security monitoring environment</b><br>
  by Mulenga Chiwele
</p>

<p align="center">
  <img alt="Tool" src="https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square">
  <img alt="Focus" src="https://img.shields.io/badge/Focus-Network%20Forensics-444?style=flat-square">
  <img alt="Role" src="https://img.shields.io/badge/Role-Security%20Analyst-8B1A1A?style=flat-square">
  <img alt="Labs" src="https://img.shields.io/badge/Labs%20completed-6-2E7D32?style=flat-square">
</p>

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Lab Environment](#lab-environment)
- [Labs Summary](#labs-summary)
- [Lab Write-ups](#lab-write-ups)
- [Wireshark Filter Cheat Sheet](#wireshark-filter-cheat-sheet)
- [Skills Demonstrated](#skills-demonstrated)
- [Methodology](#methodology)
- [Defensive Recommendations](#defensive-recommendations)
- [Key Takeaways](#key-takeaways)
- [Repository Structure](#repository-structure)
- [About the Author](#about-the-author)
- [Disclaimer](#disclaimer)

---

## Overview

This repository documents my work on a series of hands-on **packet analysis** labs from [NetworkWalks](https://networkwalks.com). In each lab I acted as a security analyst: capturing live traffic in Wireshark, filtering and inspecting packets, and drawing evidence-based conclusions about what happened on the network.

The scenarios cover reconnaissance, plaintext data exposure, credential theft, brute-force attacks and voice traffic analysis. These are situations a security analyst meets in day-to-day monitoring and incident response.

## Objectives

- Build practical skill in capturing and analyzing network traffic.
- Learn to separate normal traffic from suspicious activity.
- Practice reading application data inside TCP streams.
- Recognize common attack patterns by their network signatures.
- Document findings clearly, the way an analyst would in a report.

## Lab Environment

| Item | Details |
|------|---------|
| Platform | NetworkWalks Wireshark labs (browser-based simulation) |
| Analyst machine | Simulated Windows PC running Wireshark |
| Capture point | Network switch with a SPAN (mirror) port |
| Target network | Simulated company network (192.168.10.0/24) |
| Primary tool | Wireshark |

## Labs Summary

| # | Lab | Category | Outcome |
|:-:|-----|----------|---------|
| 3 | [Identify the Attacker's IP](#lab-3-identify-the-attackers-ip) | Reconnaissance detection | Attacker IP identified, SYN scan confirmed, open and closed ports mapped |
| 4 | [Follow TCP Stream](#lab-4-follow-tcp-stream) | Plaintext application traffic | Chat session reconstructed and shared content identified |
| 5 | [Follow TCP Stream, Part 2](#lab-5-follow-tcp-stream-part-2) | Hidden data in web content | Hidden note recovered from an HTML comment |
| 6 | [HTTP Plaintext Credentials](#lab-6-http-plaintext-credentials) | Credential exposure | Plaintext login details exposed in HTTP traffic |
| 7 | [Brute Force Catch](#lab-7-brute-force-catch) | Authentication attacks | Brute-force source identified and attack outcome determined |
| 8 | [VoIP Call Replay](#lab-8-voip-call-replay) | Voice traffic analysis | Call recovered from the capture and replayed |

---

## Lab Write-ups

### Lab 3: Identify the Attacker's IP

**Category:** Reconnaissance detection

**Scenario:** A staff member reported unusual traffic to the company web server. The task was to capture and analyze the traffic, identify the type of attack and find the attacker's IP address.

**Approach:**

1. Captured traffic on the WiFi interface and recorded the total packet count.
2. Filtered for packets that start a TCP connection:
   `tcp.flags.syn == 1 && tcp.flags.ack == 0`
3. Used **Statistics → Conversations → IPv4** to find the one source sending far more SYN packets than any other host.
4. Counted the distinct destination ports the attacker probed.
5. Filtered the server's replies to classify ports:
   - Open ports: `ip.src == <server> && tcp.flags.syn == 1 && tcp.flags.ack == 1`
   - Closed ports: `ip.src == <server> && tcp.flags.reset == 1`

**Findings:**

- A single host sent a long block of SYN packets to many different ports, which is the signature of a **SYN (half-open) port scan**.
- Open ports answered with `SYN, ACK`. Closed ports answered with `RST, ACK`.
- Normal hosts only sent one or two SYN packets, which made the attacker easy to spot.

**What I learned:** Port scans are noisy. Counting SYN packets per source is a fast way to find the scanner.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab3-1.png" alt="Lab 3: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab3-2.png" alt="Lab 3: screenshot 2" width="85%">
</p>

</details>

---

### Lab 4: Follow TCP Stream

**Category:** Plaintext application traffic

**Scenario:** Staff were using an old office chat tool that sends messages unencrypted. The task was to capture the traffic, read one chat and see what was shared.

**Approach:**

1. Removed normal web traffic to find unusual ports:
   `tcp && !(tcp.port == 80) && !(tcp.port == 443)`
2. Opened **Statistics → Conversations → TCP** to find the chat port and the host that started the connection (the sender of the first SYN).
3. Isolated the conversation with `tcp.stream eq <number>`.
4. Right-clicked a packet and chose **Follow → TCP Stream** to read the messages and check the conversation size in the bottom bar.

**Findings:**

- The chat ran on a non-standard TCP port and sent messages in clear text.
- Follow TCP Stream rebuilt the whole conversation in readable form.
- The stream number in the window title (`tcp.stream eq N`) identifies the conversation.

**What I learned:** Anything sent over an unencrypted protocol can be read by anyone who captures it.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab4-1.png" alt="Lab 4: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab4-2.png" alt="Lab 4: screenshot 2" width="85%">
</p>

</details>

---

### Lab 5: Follow TCP Stream, Part 2

**Category:** Hidden data in web content

**Scenario:** A staff member browsed the company intranet and an admin suspected someone had left a secret inside one of the web pages.

**Approach:**

1. Filtered `http.request` to list every page requested.
2. Followed the TCP stream for each page.
3. Read the server's reply (blue text) for each page, looking for unusual content.
4. Used `frame contains "<!--"` to jump straight to pages containing HTML comments.

**Findings:**

- One page contained a note inside an **HTML comment** (`<!-- ... -->`).
- Browsers do not display comments, so a normal user would never see the note, but it is fully visible in captured traffic.
- In Follow TCP Stream, **red** text is sent by the client and **blue** text is sent by the server.

**What I learned:** Hiding information in page source is not security. Anything the server sends can be read on the wire.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab5-1.png" alt="Lab 5: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab5-2.png" alt="Lab 5: screenshot 2" width="85%">
</p>

</details>

---

### Lab 6: HTTP Plaintext Credentials

**Category:** Credential exposure

**Scenario:** Investigate whether login details can be recovered from unencrypted web traffic.

**Approach:**

1. Filtered form submissions: `http.request.method == "POST"`
2. Narrowed to likely login forms: `http.request.method == "POST" && http contains "password"`
3. Inspected the packet details (**HTML Form URL Encoded** section) and followed the stream to read the submitted data.

**Findings:**

- Usernames and passwords sent over HTTP appear in clear text in the capture.
- Anyone on the same network path, or with access to a mirror port, could collect them.

**What I learned:** Login pages must use HTTPS. HTTP gives no protection for credentials.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab6-1.png" alt="Lab 6: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab6-2.png" alt="Lab 6: screenshot 2" width="85%">
</p>

</details>

---

### Lab 7: Brute Force Catch

**Category:** Authentication attacks

**Scenario:** The owner of an FTP server reported many failed sign-ins in the last few minutes. The task was to find who was guessing passwords and whether the attacker got in.

**Approach:**

1. Opened **Statistics → Protocol Hierarchy** to confirm the failed sign-ins were on **FTP**.
2. Filtered failed logins: `ftp.response.code == 530`
3. Used **Statistics → Conversations** to find the source IP behind the repeated attempts.
4. Looked for a successful login: `ftp.response.code == 230`
5. Followed the FTP stream to read the login attempts.

**Findings:**

- One source made many login attempts in quick succession, which is typical **brute-force** behaviour.
- Response code `530` means login failed, and `230` means login succeeded.
- FTP sends usernames and passwords in clear text, so the guesses were readable in the capture.

**What I learned:** Many failed logins from one source followed by a success is a key detection pattern.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab7-1.png" alt="Lab 7: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab7-2.png" alt="Lab 7: screenshot 2" width="85%">
</p>

</details>

---

### Lab 8: VoIP Call Replay

**Category:** Voice traffic analysis

**Scenario:** A phone call was made through the company VoIP system. The task was to find the call in the capture and play it back.

**Approach:**

1. Filtered the voice data with `rtp` and the call setup with `sip`.
2. Opened **Telephony → VoIP Calls** to find the call between the two extensions.
3. Selected the call and clicked **Play Streams** to replay the audio.
4. Listened to the start of the call to identify the speakers.

**Findings:**

- The call used **SIP** for setup and **RTP** to carry the audio.
- Unencrypted RTP can be reconstructed and played back from a capture.

**What I learned:** Voice traffic needs encryption (SRTP and TLS) like any other sensitive data.

<details>
<summary><b>View screenshots</b></summary>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab8-1.png" alt="Lab 8: screenshot 1" width="85%">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/USERNAME/REPO-NAME/main/screenshots/lab8-2.png" alt="Lab 8: screenshot 2" width="85%">
</p>

</details>

---

## Wireshark Filter Cheat Sheet

| Purpose | Filter |
|---------|--------|
| Connection-starting packets (SYN) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Open-port replies (SYN, ACK) | `ip.src == <server> && tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Closed-port replies (RST) | `ip.src == <server> && tcp.flags.reset == 1` |
| Traffic from one host | `ip.src == 192.168.10.20` |
| Traffic on a specific port | `tcp.port == 5000` |
| Exclude web traffic | `!(tcp.port == 80) && !(tcp.port == 443)` |
| One TCP conversation | `tcp.stream eq 5` |
| HTTP requests | `http.request` |
| HTTP form submissions | `http.request.method == "POST"` |
| HTML comments in traffic | `frame contains "<!--"` |
| FTP failed logins | `ftp.response.code == 530` |
| FTP successful logins | `ftp.response.code == 230` |
| VoIP signalling | `sip` |
| VoIP audio | `rtp` |

## Skills Demonstrated

| Area | Details |
|------|---------|
| **Traffic capture** | Capturing live traffic and analyzing packet captures in Wireshark |
| **Display filters** | Isolating traffic by protocol, port, flags, stream and host |
| **Statistical analysis** | Conversations, Endpoints and Protocol Hierarchy to find patterns in large captures |
| **Stream reconstruction** | Rebuilding sessions with Follow TCP Stream to read application data |
| **Threat identification** | Recognizing port scans, brute-force attempts and plaintext credential exposure |
| **Protocol knowledge** | TCP handshake and flags, HTTP, FTP response codes, SIP and RTP |
| **VoIP analysis** | Inspecting SIP signalling and replaying RTP audio streams |
| **Documentation** | Recording evidence and conclusions clearly |

## Methodology

1. **Capture** the relevant traffic on the correct network interface.
2. **Scope** the data with display filters to remove normal background traffic.
3. **Analyze** with Wireshark's statistics tools to find unusual sources, ports or volumes.
4. **Inspect** individual packets and streams to confirm the findings.
5. **Document** the evidence and conclusions.

## Defensive Recommendations

| Finding | Recommended control |
|---------|---------------------|
| Port scanning | Firewall rules, rate limiting, intrusion detection alerts on SYN floods and scans |
| Plaintext chat, HTTP and FTP | Replace with encrypted alternatives (HTTPS, SFTP or FTPS, secure messaging) |
| Secrets in page source | Never store sensitive data in HTML. Keep secrets on the server side |
| Brute-force logins | Account lockout, rate limiting, multi-factor authentication, fail2ban-style blocking |
| Unencrypted VoIP | Use SRTP and TLS for call signalling and audio |

## Key Takeaways

- Attackers leave recognizable patterns in network traffic, such as many SYN packets from one source or repeated failed logins.
- Unencrypted protocols expose credentials and messages to anyone who can capture the traffic.
- Well-chosen display filters and Wireshark's statistics views turn thousands of packets into a clear answer.
- Content hidden from users in a browser, such as HTML comments, is still fully visible on the wire.
- Knowing normal behaviour makes abnormal behaviour much easier to see.

## Repository Structure

```
.
├── README.md
└── screenshots/
    ├── lab3-1.png
    ├── lab3-2.png
    ├── lab4-1.png
    ├── lab4-2.png
    ├── lab5-1.png
    ├── lab5-2.png
    ├── lab6-1.png
    ├── lab6-2.png
    ├── lab7-1.png
    ├── lab7-2.png
    ├── lab8-1.png
    └── lab8-2.png
```

## About the Author

**Mulenga Chiwele**
Aspiring Security Analyst | Network Security

I am building hands-on skills in network traffic analysis and incident investigation, with a focus on Wireshark, protocol analysis and threat detection.

- GitHub:https://github.com/mulengachiwele174-afk
- LinkedIn:www.linkedin.com/in/mulenga-chiwele-712a64365
- Email: Mulengachiwele174@gmail.com

## Disclaimer

All labs were completed in a safe, simulated training environment provided by [NetworkWalks](https://networkwalks.com). No real systems, networks or personal data were involved. This repository is for educational purposes only.

---

<p align="center">
  <sub>Thanks for reading.</sub>
</p>
