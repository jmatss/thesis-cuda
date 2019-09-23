# IoT Penetration Testing: Security analysis of a car dongle 
Proof of concept for hack on AutoPi found during bachelor thesis ([link](https://www.diva-portal.org/smash/record.jsf?pid=diva2%3A1334244), CVE-2019-12941).

## Vulnerability
The Raspberry Pi which the AutoPi is built upon, has a unique 8 character hex serial number. This number is md5 hashed into a 32 character hex string, also known as the “dongle id“, “unit id” or “minion id” [[row 9]](https://github.com/autopi-io/autopi-core/blob/3507b5ff420c9e7af3aa88b0b1cf4b68e677b36a/src/salt/base/state/minion/install.sls). The dongle id is a unique identifier of the AutoPi dongle and the first 6 bytes are used as wifi password while the last 6 bytes are used as wifi SSID. This means that one can deduce the the wifi password from the broadcasted SSID. Root access is given if connected to the AutoPi dongle via wifi. 

**crackwifi** takes a SSID as arguments, runs through all possibles hashes and retreives the correct wifi password in less than a second. Requires a nvidia graphics card. Adapted from http://macs-site.net/md5oncudawhitepaper.html.

```
Usage:  crackwifi <12 hex SSID>
```

```
C:\thesis>nvcc crackwifi.cu -o crackwifi >NUL && crackwifi 38676c1698f0
Serial:    00000000ad993618
Hash:      392c797ca4ea72d6797d38676c1698f0
SSID:      AutoPi-38676c1698f0
Password:  392c797ca4ea
```
