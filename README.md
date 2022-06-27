# Cisco ASA Research

This repository contains slides and code presented at Black Hat USA 2022 and DEF CON 30. The following can be found:

* [theway](https://github.com/jbaines-r7/theway) - a tool for creating malicious/distributable ASDM packages for the Cisco ASA ([CVE-2022-20829](https://nvd.nist.gov/vuln/detail/CVE-2022-20829)).
* [whatsup](https://github.com/jbaines-r7/whatsup) - a tool for creating malicious/distributable Cisco FirePOWER module installation packages (No CVE).
* [pinchme](https://github.com/jbaines-r7/pinchme) - a tool for creating malicious/distributable Cisco FirePOWER boot images (No CVE).
* [staystaystay](https://github.com/jbaines-r7/staystaystay) - a stand-alone exploit for [CVE-2021-1585](https://nvd.nist.gov/vuln/detail/CVE-2021-1585), an unath RCE vulnerability affecting Cisco ASDM.
* [asdm_version_scanner](https://github.com/jbaines-r7/asdm_version_scanner) - a tool for scanning ASA ASDM web interfaces and collecting versions. The repository contains results from an internet scan conducted on June 17, 2022.
* [getchoo](https://github.com/jbaines-r7/getchoo) - a tool for extracting the contents of an ASDM sgz file.
* `modules/` (Metasploit):
  * An RCE module for [CVE-2022-20828](https://nvd.nist.gov/vuln/detail/CVE-2022-20828): Remote ASDM -> FirePOWER root.
  * An RCE module for [CVE-2021-1585](https://nvd.nist.gov/vuln/detail/CVE-2021-1585): Unauthenticated RCE affecting ASDM *client*.
  * A PackRat post-exploitation module to extract credentials from ASDM client log files ([CVE-2022-20651](https://nvd.nist.gov/vuln/detail/CVE-2022-20651))
  * An ASDM (HTTP) brute-force authentication module.
  * A module for dumping the ASA running-config over ASDM (HTTP).
* `yara/` contains [YARA](https://virustotal.github.io/yara/) rules to help identify malicious files or exploitation.
* `slides/` contains the slide decks presented at BH USA 2022 and DEF CON 30.
