# acme-ddns

DNS server that supports RFC2136 dynamic updates for handling ACME DNS challenges.

## Simple usage

### generate tsig keys

```
% tsig-keygen mykey
key "mykey" {
        algorithm hmac-sha256;
        secret "8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=";
};
```

algorithm should be hmac-sha256.

### run dns server

```
% ./acme-ddns --domain example.com --keyname mykey --secret '8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=' --listen ':8053'
```

### test with dig

DNS server responses NXDOMAIN because no updates yet.

```
% dig -p 8053  @127.0.0.1 _acme-challenge.example.com txt

; <<>> DiG 9.10.6 <<>> -p 8053 @127.0.0.1 _acme-challenge.example.com txt
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3540
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;_acme-challenge.example.com.   IN      TXT

;; AUTHORITY SECTION:
_acme-challenge.example.com. 3600 IN    SOA     ns.example.com. ns.example.com. 1 3600 900 2419200 30

;; Query time: 0 msec
;; SERVER: 127.0.0.1#8053(127.0.0.1)
;; WHEN: Wed May 17 17:42:23 JST 2023
;; MSG SIZE  rcvd: 136
```

### update by nsupdate command

```
% cat server.txt 
server 127.0.0.1 8053
zone example.com.
update delete _acme-challenge.example.com. 3600 TXT
update add _acme-challenge.example.com. 3600 TXT "BHVgrXVuoykwwgtYmzMBksiLzBBVsrfQXCG2dGkx"
send

% nsupdate -d -p 8053 -y 'hmac-sha256:mykey.:8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=' server.txt 
Creating key...
namefromtext
keycreate
Sending update to 127.0.0.1#8053
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:    355
;; flags:; ZONE: 1, PREREQ: 0, UPDATE: 2, ADDITIONAL: 1
;; ZONE SECTION:
;example.com.                   IN      SOA

;; UPDATE SECTION:
_acme-challenge.example.com. 0  ANY     TXT
_acme-challenge.example.com. 3600 IN    TXT     "BHVgrXVuoykwwgtYmzMBksiLzBBVsrfQXCG2dGkx"

;; TSIG PSEUDOSECTION:
mykey.                  0       ANY     TSIG    hmac-sha256. 1684312840 300 32 C4xi+scphfXJoQ6MVOvbXAuEW6NoonG5KbtcM0Lz+hk= 355 NOERROR 0 


Reply from update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:    355
;; flags: qr aa; ZONE: 1, PREREQ: 0, UPDATE: 0, ADDITIONAL: 1
;; ZONE SECTION:
;example.com.                   IN      SOA

;; TSIG PSEUDOSECTION:
mykey.                  0       ANY     TSIG    hmac-sha256. 1684312840 300 32 TYCx7moOnqRxNnqaDem+G5F3BO+DP+2wFYaI6ITClYM= 355 NOERROR 0 

```

### resolve by dig

DNS server responses a TXT record you want.

```
% dig -p 8053  @127.0.0.1 _acme-challenge.example.com txt    

; <<>> DiG 9.10.6 <<>> -p 8053 @127.0.0.1 _acme-challenge.example.com txt
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36662
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;_acme-challenge.example.com.   IN      TXT

;; ANSWER SECTION:
_acme-challenge.example.com. 3600 IN    TXT     "BHVgrXVuoykwwgtYmzMBksiLzBBVsrfQXCG2dGkx"

;; AUTHORITY SECTION:
_acme-challenge.example.com. 3600 IN    SOA     ns.example.com. ns.example.com. 1 3600 900 2419200 30

;; Query time: 0 msec
;; SERVER: 127.0.0.1#8053(127.0.0.1)
;; WHEN: Wed May 17 17:41:47 JST 2023
;; MSG SIZE  rcvd: 216
```

## TTL and cache

acme-ddns caches TXT record for specified time (default 3 hours)


## command args

```
% ./acme-ddns -h                                                                                                           
Usage:
  acme-ddns [OPTIONS]

Application Options:
  -v, --version     Show version
      --listen=     address for listen (default: :8053)
      --ttl=        ttl for TXT (default: 1h)
      --expiration= expiration time for cache TXT record (default: 3h)
      --domain=     zone name for dynamic dns
      --keyname=    Name of TSIG key
      --secret=     secret of TSIG key
      --ns-name=    NS record name of the zone (default: ns)
      --ns-addr=    NS record value of the zone (default: 127.0.0.1)

Help Options:
  -h, --help        Show this help message
```

