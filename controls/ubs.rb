control 'UBS-1' do
  impact 1.0
  title 'Check that the "UBS" file exits'
  desc 'A critical security file must always be installed on every machine'
  describe file('/ubscheck') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('type') { should cmp 'file' }
    its('md5sum') { should eq 'd41d8cd98f00b204e9800998ecf8427e' }
    its('mode') { should cmp '0644' }
  end
end

require_controls 'ubuntu' do
  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.4_Ensure_telnet_client_is_not_installed'
  control 'xccdf_org.cisecurity.benchmarks_rule_5.2.9_Ensure_SSH_PermitEmptyPasswords_is_disabled'
  control 'xccdf_org.cisecurity.benchmarks_rule_6.2.20_Ensure_shadow_group_is_empty'
end

# include_controls 'ubuntu' do
#   skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.3.4_Ensure_telnet_client_is_not_installed'
# end