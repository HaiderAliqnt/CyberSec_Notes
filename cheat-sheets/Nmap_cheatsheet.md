# Nmap Cheat Sheet and Notes

**Made by:** Muhammad Haider Ali

---

## What is Nmap:

Nmap also known as Network Mapper is basically a tool that allows you to do reconnaissance work by looking at ports over a range of IP or even a specific IP. 

It performs a three-way syn handshake with the target to identify whether it is open, closed or filtered. Hence it shows up quite easily and can be blocked by firewalls.

**Open:** Port has a running service and can be accessed  
**Closed:** Port has a running service but cannot be accessed  
**Filtered:** Nmap cannot decide or blocked by firewall

**TCP connection:** Does form a connection with the port and is used by nmap to scan the ports.  
**UDP connection:** Compared to TCP, UDP does not really form a connection with the ports instead only transmits data.

**Levels of verbosity:** Information being provided by nmap  
`-v` : Single level, gives scan progress only  
`-vv` : Double level, gives more information like ARP responses  
`-vvv` : Triple level, gives even more information like DNS resolutions

**NORMAL TCP FLAG PATTERN:**  
SYN → SYN-ACK → ACK → DATA TRANSFER → FIN → RST

---

## Useful Commands:

### Help & Documentation

**man nmap**  
(Displays the manual pages for nmap tool)

**nmap --help**  
(Help command to give summary of the nmap command)

---

### Basic Scanning

**nmap \<website address\>**  
(Scans the website for open ports)  
Example: `nmap scanme.nmap.org`

**nmap \<ip/web address\> \<ip/web address\>**  
(A method to scan multiple ips or web addresses together)

**nmap --open \<ip/web address\>**  
(Only scans for open ports)

---

### Host Discovery

**nmap -sn \<target ip range\>**  
(Does a ping sweep to check which hosts are active on the network with their mac addresses as well, used for host discovery with ICMP echo requests but they may be blocked by the firewall)  
Example: `nmap -sn 192.168.1.0/24`

**nmap -Pn \<target ip\>**  
(Skips the ping sweep since some hosts can be alive, but they might be configured to not reply to pings hence this command assumes that the host is alive and directly goes to the scanning part for either ports, version or the OS)

---

### Port Specification

**nmap -p \<port number\> \<ip/web address\>**  
(Scans specific port)  
Example: `nmap -p 22 192.168.1.10`

**nmap -p \<port range\> \<ip/web address\>**  
(Scans range of ports)  
Example: `nmap -p 1-1000 192.168.1.10`

**nmap -p- \<ip/web address\>**  
(Scans all 65535 ports)  
Example: `nmap -p- 192.168.1.10`

**nmap --top-ports \<number\> \<ip/web address\>**  
(Scans the most common ports, specify how many)  
Example: `nmap --top-ports 100 192.168.1.10`

---

### Service & OS Detection

**nmap -O \<ip/web address\>**  
(Shows the possible operating system the target is running and displays it in order of the highest probability to the lowest)

**nmap -sV \<ip/web address\>**  
(sV refers to scan service version so you can better decide on which exploit to run)

**nmap -A \<ip/web address\>**  
(A refers to aggressive scanning hence provides more info than a regular scan, it enables OS detection, version detection, script scanning and traceroutes)

---

### Timing Templates

**nmap -T0 \<ip/web address\>**  
(Paranoid - slowest timing, used for IDS evasion, waits 5 minutes between probes)

**nmap -T1 \<ip/web address\>**  
(Sneaky - very slow, used for IDS evasion, waits 15 seconds between probes)

**nmap -T2 \<ip/web address\>**  
(Polite - slows down to use less bandwidth, waits 0.4 seconds between probes)

**nmap -T3 \<ip/web address\>**  
(Normal - default timing, balanced speed and accuracy)

**nmap -T4 \<ip/web address\>**  
(Aggressive - faster scanning, recommended for CTFs and most pentests, assumes good network)

**nmap -T5 \<ip/web address\>**  
(Insane - fastest possible, may sacrifice accuracy, only use on very fast networks)

---

### Speed Options

**nmap -F \<ip/web address\>**  
(F refers to Fast and basically instead of default scanning 1000 ports it only targets the more common ports such as 22(ssh) and 80(http))

---

### Scan Types

**nmap -sT \<ip/web address\>**  
(Only scans for TCP connections, forms complete connection with target)

**nmap -sU \<ip/web address\>**  
(Only scans for UDP connections, used to bypass firewall since no connection is being made, it also doesn't display any output like open but instead only displays output when port is closed in the form "port not reachable")

**nmap -sS \<ip/web address\>**  
(S refers to a stealth scan and doesn't initiate the traditional 3-way handshake by not responding to the target's ack signal, this basically doesn't even create a connection hence some firewalls don't detect it)

**nmap -sF \<ip/web address\>**  
(Sends a packet with only FIN flag set. Closed ports respond with RST and open ports ignore the packet. Command limited for Linux users)

**nmap -sN \<ip/web address\>**  
(Sends a null packet with no flags set, closed ports respond with RST and open ports ignore the packet)

**nmap -sX \<ip/web address\> --reason**  
(Sends packets with FIN, URG, PSH resembling a lit Christmas tree, closed ports reply with RST and open ports do not respond, the reason flag explains the reason for why the port was categorized as such)

**nmap -sA \<ip/web address\> --reason**  
(Sends ACK packets to detect whether there is a firewall present or not, if there is a firewall no response is sent back but if there is no firewall then we get an RST signal back)

---

### Output Formats

**nmap -oN \<filename\> \<ip/web address\>**  
(Saves output in normal human-readable format)  
Example: `nmap -oN scan_results.txt 192.168.1.10`

**nmap -oX \<filename\> \<ip/web address\>**  
(Saves output in XML format for parsing with tools)  
Example: `nmap -oX scan_results.xml 192.168.1.10`

**nmap -oG \<filename\> \<ip/web address\> -vv**  
(oG formats the data into a greppable format, v (verbose) basically ensures all info is listed in the output and then the command stores the data into the given directory)  
Example: `nmap -oG scan_results.gnmap 192.168.1.0-255 -vv`

**nmap -oA \<filename\> \<ip/web address\>**  
(Saves output in all three formats at once: normal, XML, and greppable)  
Example: `nmap -oA complete_scan 192.168.1.10 -vv -p 22`

---

### Evasion Techniques

**nmap -D \<decoy ip/use the random function RND:3\> \<target ip/web address\>**  
(D basically creates a decoy ip so the signal being sent to the target can't be traced back to the original host. RND function creates 3 random IPs)  
Example: `nmap -D RND:3 192.168.1.10`

**nmap -D -f \<decoy ip/use the random function RND:3\> \<target ip/web address\>**  
(f option allows us to fragment the packet into smallest units possible but now doesn't work because modern firewalls can easily build the packets again, you can use -mtu (minimum transmission unit) option as well -mtu 16 forms 16 byte packets)  
Example: `nmap -D -f RND:3 192.168.1.10`

**nmap --source-port \<port\> \<ip/web address\>**  
(Spoofs source port to bypass firewall rules that allow traffic from specific ports)  
Example: `nmap --source-port 53 192.168.1.10` (spoofs DNS port)

**nmap --data-length \<number\> \<ip/web address\>**  
(Adds random data to packets to change packet size and evade detection)  
Example: `nmap --data-length 25 192.168.1.10`

---

## NMAP SCRIPTS (NSE):

Automated scripts are available according to their categories on the nmap official site. You can include those while scanning to improve efficiency.

**nmap --script \<script/category name\> \<target ip/web address\>**  
Example: `nmap --script vuln 10.7.1.226`  
(The command uses every script with the vuln category to scan the specified port)

### Common Script Categories:

**nmap --script default \<ip/web address\>**  
(Runs default safe scripts for basic enumeration)

**nmap --script vuln \<ip/web address\>**  
(Runs vulnerability detection scripts, checks for known CVEs)

**nmap --script exploit \<ip/web address\>**  
(Runs exploitation scripts, be careful with these in production)

**nmap --script auth \<ip/web address\>**  
(Tests authentication mechanisms, checks for weak credentials)

**nmap --script discovery \<ip/web address\>**  
(Network and service discovery scripts)

**nmap --script brute \<ip/web address\>**  
(Brute force attack scripts for various services)

### Useful Specific Scripts:

**nmap --script ftp-anon \<ip/web address\> -p 21**  
(Checks if FTP allows anonymous login)

**nmap --script smb-enum-shares \<ip/web address\> -p 445**  
(Enumerates SMB shares on Windows systems)

**nmap --script http-enum \<ip/web address\> -p 80**  
(Enumerates directories and files on web server)

**nmap --script ssh-brute \<ip/web address\> -p 22**  
(Brute forces SSH login credentials)

**nmap --script mysql-empty-password \<ip/web address\> -p 3306**  
(Checks for MySQL accounts with empty passwords)

**nmap --script dns-zone-transfer \<domain\>**  
(Attempts DNS zone transfer to enumerate subdomains)

### Script Help:

**nmap --script-help \<script name\>**  
(Shows help information for specific script)  
Example: `nmap --script-help ftp-anon`

**ls /usr/share/nmap/scripts/ | grep \<keyword\>**  
(Lists all available scripts matching keyword)  
Example: `ls /usr/share/nmap/scripts/ | grep http`

---

## Common Ports Reference:

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Unencrypted remote access |
| 25 | SMTP | Email transmission |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Web traffic |
| 110 | POP3 | Email retrieval |
| 111 | RPC | Remote Procedure Call |
| 135 | MSRPC | Microsoft RPC |
| 139 | NetBIOS | Windows file sharing |
| 143 | IMAP | Email retrieval |
| 443 | HTTPS | Encrypted web traffic |
| 445 | SMB | Windows file sharing |
| 3306 | MySQL | MySQL database |
| 3389 | RDP | Remote Desktop Protocol |
| 5432 | PostgreSQL | PostgreSQL database |
| 5900 | VNC | Virtual Network Computing |
| 8080 | HTTP-Proxy | Alternative HTTP port |

---

## CTF Quick Wins:

### Quick Initial Recon:
```bash
nmap -sV --top-ports 1000 -T4 <target> -oN quick_scan.txt
```
(Fast scan of common ports with version detection)

### Full Comprehensive Scan:
```bash
sudo nmap -A -p- -T4 <target> -oA full_scan
```
(Aggressive scan of all ports with OS/version detection and scripts)

### Stealth Vulnerability Scan:
```bash
sudo nmap -sS --script vuln -T2 <target> -oN vuln_scan.txt
```
(Stealthy scan checking for vulnerabilities)

### Web Server Enumeration:
```bash
nmap --script http-enum -p 80,443,8080 <target>
```
(Finds hidden directories and files on web servers)

### SMB Enumeration:
```bash
nmap --script smb-enum-shares,smb-enum-users -p 445 <target>
```
(Enumerates SMB shares and users on Windows targets)

### Check for Anonymous FTP:
```bash
nmap --script ftp-anon -p 21 <target>
```
(Checks if FTP allows anonymous access - easy win!)

---

## Troubleshooting:

**No results showing:**
- Try `-Pn` to skip host discovery
- Use `sudo` for SYN scans and OS detection
- Check if target is actually up with `ping`

**Scan is too slow:**
- Use `-T4` for faster timing
- Reduce port range with `--top-ports 100`
- Use `-F` for fast scan of common ports only

**Permission denied errors:**
- Use `sudo` for raw packet scans (-sS, -sU, -O)
- Regular user can only do `-sT` (TCP connect)

**Firewall blocking scans:**
- Try stealth scan with `-sS`
- Use decoys with `-D RND:3`
- Fragment packets with `-f`
- Try different source ports with `--source-port 53`

**"Too many open files" error:**
- Reduce timing with `-T2` or `-T3`
- Scan fewer hosts at once
- Use `ulimit -n 4096` to increase file limit

---

## Pro Tips for CTF:

1. **Always start with quick scan** - Don't waste time scanning all ports initially
2. **Version detection is key** - Use `-sV` to identify exploitable versions
3. **Check for low-hanging fruit** - Anonymous FTP, default credentials, open SMB shares
4. **Combine with other tools** - Use nmap results to feed into Metasploit, searchsploit
5. **Save everything** - Use `-oA` to save all output formats for later reference
6. **UDP matters** - Don't forget `-sU`, some services only run on UDP
7. **Scripts are your friend** - NSE scripts automate common checks
8. **Read the output carefully** - Version numbers, service banners contain hints
9. **Check uncommon ports** - Sometimes services run on non-standard ports
10. **Timeout patience** - Some scans take time, use `-T4` to speed up in CTF environment

---

**Last Updated:** February 2026  
