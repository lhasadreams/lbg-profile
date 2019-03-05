control 'LBG-1' do   
  impact 1.0
  title 'Check that the "LBG" file exits'
  desc 'A critical security file must always be installed on every machine'
  describe file('/lbgcheck') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('type') { should cmp 'file' }
    its('md5sum') { should eq 'd41d8cd98f00b204e9800998ecf8427e' }
    its('mode') { should cmp '0644' }
  end
end

require_controls 'mac' do
  control 'xccdf_org.cisecurity.benchmarks_rule_1.1_Verify_all_Apple_provided_software_is_current'
  control 'xccdf_org.cisecurity.benchmarks_rule_4.2_Enable_Show_Wi-Fi_status_in_menu_bar'
end

#include_controls 'ubuntu'
