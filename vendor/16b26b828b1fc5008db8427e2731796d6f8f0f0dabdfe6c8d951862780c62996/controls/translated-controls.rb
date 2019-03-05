control "xccdf_org.cisecurity.benchmarks_rule_1.1_Verify_all_Apple_provided_software_is_current" do
  title "Verify all Apple provided software is current"
  desc  "
    Software vendors release security patches and software updates for their products when security vulnerabilities are discovered. There is no simple way to complete this action without a network connection to an Apple software repository. Please ensure appropriate access for this control. This check is only for what Apple provides through software update.
    
    Rationale: It is important that these updates be applied in a timely manner to prevent unauthorized persons from exploiting the identified vulnerabilities.
  "
  impact 1.0
  describe bash("/usr/sbin/softwareupdate -l 2>&1") do
    its("stdout") { should match(/No new software available/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2_Enable_Auto_Update" do
  title "Enable Auto Update"
  desc  "
    Auto Update verifies that your system has the newest security patches and software updates. If \"Automatically check for updates\" is not selected background updates for new malware definition files from Apple for XProtect and Gatekeeper will not occur.
    
    http://macops.ca/os-x-admins-your-clients-are-not-getting-background-security-updates/
    
    https://derflounder.wordpress.com/2014/12/17/forcing-xprotect-blacklist-updates-on-mavericks-and-yosemite/
    
    Rationale: It is important that a system has the newest updates applied so as to prevent unauthorized persons from exploiting identified vulnerabilities.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled") do
    its("stdout") { should match(/1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.3_Enable_app_update_installs" do
  title "Enable app update installs"
  desc  "
    Ensure that application updates are installed after they are available from Apple. These updates do not require reboots or admin privileges for end users.
    
    Rationale: Patches need to be applied in a timely manner to reduce the risk of vulnerabilities being exploited
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.storeagent AutoUpdate") do
    its("stdout") { should match(/^1$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.4_Enable_system_data_files_and_security_update_installs" do
  title "Enable system data files and security update installs"
  desc  "
    Ensure that system and security updates are installed after they are available from Apple. This setting enables definition updates for XProtect and Gatekeeper, with this setting in place new malware and adware that Apple has added to the list of malware or untrusted software will not execute. These updates do not require reboots or end user admin rights.
    
    http://www.thesafemac.com/tag/xprotect/
    
    https://support.apple.com/en-us/HT202491
    
    Rationale: Patches need to be applied in a timely manner to reduce the risk of vulnerabilities being exploited
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.SoftwareUpdate | egrep 'ConfigDataInstall'") do
    its("stdout") { should match(/ConfigDataInstall = 1;/) }
  end
  describe bash("defaults read /Library/Preferences/com.apple.SoftwareUpdate | egrep 'CriticalUpdateInstall'") do
    its("stdout") { should match(/CriticalUpdateInstall = 1;/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5_Enable_OS_X_update_installs" do
  title "Enable OS X update installs"
  desc  "
    Ensure that OS X updates are installed after they are available from Apple. This setting enables OS X updates to be automatically installed. Some environments will want to approve and test updates before they are delivered. It is best practice to test first where updates can and have caused disruptions to operations. Automatic updates should be turned off where changes are tightly controlled and there are mature testing and approval processes. Automatic updates should not be turned off so the admin can call the users first to let them know it's ok to install. A dependable repeatable process involving a patch agent or remote management tool should be in place before auto-updates are turned off.
    
    Rationale: Patches need to be applied in a timely manner to reduce the risk of vulnerabilities being exploited
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired") do
    its("stdout") { should match(/1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.1_Turn_off_Bluetooth_if_no_paired_devices_exist" do
  title "Turn off Bluetooth, if no paired devices exist"
  desc  "
    Bluetooth devices use a wireless communications system that replaces the cables used by other peripherals to connect to a system. It is by design a peer-to-peer network technology and typically lacks centralized administration and security enforcement infrastructure.
    
    Rationale: Bluetooth is particularly susceptible to a diverse set of security vulnerabilities involving identity detection, location tracking, denial of service, unintended control and access of data and voice channels, and unauthorized device control and data access.
  "
  impact 1.0
  describe bash("STATE=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState); PAIRED=$(system_profiler SPBluetoothDataType | grep \"Connectable\" | awk '{print $2}'); echo \"Enabled=$STATE;Paired=$PAIRED\"") do
    its("stdout") { should match(/^(Enabled=0|Enabled=1;Paired=Yes)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.2_Turn_off_Bluetooth_Discoverable_mode_when_not_pairing_devices" do
  title "Turn off Bluetooth \"Discoverable\" mode when not pairing devices"
  desc  "
    When Bluetooth is set to discoverable mode, the Mac sends a signal indicating that it's available to pair with another Bluetooth device. When a device is \"discoverable\" it broadcasts information about itself and it's location. Starting with OS X 10.9 Discoverable mode is enabled while the Bluetooth System Preference is open and turned off once closed. Systems that have the Bluetooth System Preference open at the time of audit will show as Discoverable.
    
    Rationale: When in the discoverable state an unauthorized user could gain access to the system by pairing it with a remote device.
  "
  impact 1.0
  describe bash("system_profiler SPBluetoothDataType | grep \"Discoverable:\"") do
    its("stdout") { should match(/Off/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.3_Show_Bluetooth_status_in_menu_bar" do
  title "Show Bluetooth status in menu bar"
  desc  "
    By showing the Bluetooth status in the menu bar, a small Bluetooth icon is placed in the menu bar. This icon quickly shows the status of Bluetooth, and can allow the user to quickly turn Bluetooth on or off.
    
    Rationale: Enabling \"Show Bluetooth status in menu bar\" is a security awareness method that helps understand the current state of Bluetooth, including whether it is enabled, Discoverable, what paired devices exist and are currently active.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.systemuiserver; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF menuExtras 2>&1 | grep Bluetooth.menu || echo 'Not Set'; fi; done") do
    its("stdout") { should_not match(/Not Set$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.2_Ensure_time_set_is_within_appropriate_limits" do
  title "Ensure time set is within appropriate limits"
  desc  "
    Correct date and time settings are required for authentication protocols, file creation, modification dates and log entries. Ensure that time on the computer is within acceptable limits. Truly accurate time is measured within milliseconds, for this audit a drift under four and a half minutes passes the control check. Since Kerberos is one of the important features of OS X integration into Directory systems the guidance here is to warn you before there could be an impact to operations. From the perspective of accurate time this check is not strict, it may be too great for your organization, adjust to a smaller offset value as needed.
    
    Rationale: Kerberos may not operate correctly if the time on the Mac is off by more than 5 minutes. This in turn can affect Apple's single sign-on feature, Active Directory logons, and other features. Audit check is for more than 4 minutes and 30 seconds ahead or behind.
  "
  impact 1.0
  describe bash("ntpdate -d $(grep ^server /etc/ntp.conf|sed 's/^server //')|tail -1|sed 's/^.*offset //'") do
    its("stdout") { should match(/^-?([0-9]{1,2}|1[0-9]{2}|2[0-6][0-9])(\.[0-9]+)? sec$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.3_Restrict_NTP_server_to_loopback_interface" do
  title "Restrict NTP server to loopback interface"
  desc  "
    The Apple System Preference setting to \"Set date and time automatically\" enables both an NTP client that can synchronize the time from known time server(s) and an open listening NTP server that can be used by any other computer that can connect to port 123 on the time syncing computer. This open listening service can allow for both exploits of future NTP vulnerabilities and allow for open ports that can be used for fingerprinting to target exploits. Access to this port should be restricted.
    
    Editing the /etc/ntp-restrict.conf file by adding a control on the loopback interface limits external access.
    
    Add the following
    
    restrict lo
    
    interface ignore wildcard
    
    
    
    interface listen lo
    
    Rationale: Mobile workstations on untrusted networks should not have open listening services available to other nodes on the network.
  "
  impact 1.0
  describe bash("cat /etc/ntp-restrict.conf") do
    its("stdout") { should match(/^restrict lo$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1_Set_an_inactivity_interval_of_20_minutes_or_less_for_the_screen_saver" do
  title "Set an inactivity interval of 20 minutes or less for the screen saver"
  desc  "
    A locking screensaver is one of the standard security controls to limit access to a computer and the current user's session when the computer is temporarily unused or unattended. In OS X the screensaver starts after a value selected in a drop down menu, 10 minutes and 20 minutes are both options and either is acceptable. Any value can be selected through the command line or script but a number that is not reflected in the GUI can be problematic. 20 minutes is the default for new accounts.
    
    Rationale: Setting an inactivity interval for the screensaver prevents unauthorized persons from viewing a system left unattended for an extensive period of time.
  "
  impact 1.0
  describe bash("UUID=`ioreg -rd1 -c IOPlatformExpertDevice | grep \"IOPlatformUUID\" | sed -e 's/^.* \"\\(.*\\)\"$/\\1/'`; for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/ByHost/com.apple.screensaver.$UUID; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF.plist idleTime 2>&1; fi; done") do
    its("stdout") { should_not match(/\s0*(0|[1-9][0-9]{4,}|[2-9][0-9]{3}|1[3-9][0-9]{2}|12[1-9][0-9]|120[1-9])$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.3_Verify_Display_Sleep_is_set_to_a_value_larger_than_the_Screen_Saver" do
  title "Verify Display Sleep is set to a value larger than the Screen Saver"
  desc  "
    If the Screen Saver is used to lock the screen, verify the Display Sleep settings are longer than the Screen Saver setting. If the display goes to sleep before the screen saver activates, the computer will appear to be off, but will be unprotected.
    
    Rationale: Users of the system can easily assume that the computer is protected when the display goes to sleep. The computer should be configured so that the screen is locked whenever the display turns off automatically.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.4_Set_a_screen_corner_to_Start_Screen_Saver" do
  title "Set a screen corner to Start Screen Saver"
  desc  "
    The intent of this control is to resemble control-alt-delete on Windows Systems as a means of quickly locking the screen. If the user of the system is stepping away from the computer the best practice is to lock the screen and setting a hot corner is an appropriate method.
    
    Rationale: Ensuring the user has a quick method to lock their screen may reduce opportunity for individuals in close physical proximity of the device to see screen contents.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.dock; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User '$i': \"; defaults read $PREF | egrep 'corner' | egrep '5;$' || echo \"Not set\"; fi; done") do
    its("stdout") { should_not match(/Not set$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.1_Disable_Remote_Apple_Events" do
  title "Disable Remote Apple Events"
  desc  "
    Apple Events is a technology that allows one program to communicate with other programs. Remote Apple Events allows a program on one computer to communicate with a program on a different computer.
    
    Rationale: Disabling Remote Apple Events mitigates the risk of an unauthorized program gaining access to the system.
  "
  impact 1.0
  describe bash("systemsetup -getremoteappleevents") do
    its("stdout") { should_not match(/Remote Apple Events: On/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.2_Disable_Internet_Sharing" do
  title "Disable Internet Sharing"
  desc  "
    Internet Sharing uses the open source natd process to share an internet connection with other computers and devices on a local network. This allows the Mac to function as a router and share the connection to other, possibly unauthorized, devices.
    
    Rationale: Disabling Internet Sharing reduces the remote attack surface of the system.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/SystemConfiguration/com.apple.nat") do
    its("stdout") { should_not match(/Enabled\s*=\s*1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.3_Disable_Screen_Sharing" do
  title "Disable Screen Sharing"
  desc  "
    Screen sharing allows a computer to connect to another computer on a network and display the computer#x2019;s screen. While sharing the computer#x2019;s screen, the user can control what happens on that computer, such as opening documents or applications, opening, moving, or closing windows, and even shutting down the computer.
    
    Rationale: Disabling screen sharing mitigates the risk of remote connections being made without the user of the console knowing that they are sharing the computer.
  "
  impact 1.0
  describe bash("launchctl list | grep com.apple.screensharing") do
    its("stdout") { should_not match(/./) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.4_Disable_Printer_Sharing" do
  title "Disable Printer Sharing"
  desc  "
    By enabling Printer sharing the computer is set up as a print server to accept print jobs from other computers. Dedicated print servers or direct IP printing should be used instead.
    
    Rationale: Disabling Printer Sharing mitigates the risk of attackers attempting to exploit the print server to gain access to the system.
  "
  impact 1.0
  describe bash("system_profiler SPPrintersDataType ") do
    its("stdout") { should_not match(/Shared: Yes/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.5_Disable_Remote_Login" do
  title "Disable Remote Login"
  desc  "
    Remote Login allows an interactive terminal connection to a computer.
    
    Rationale: Disabling Remote Login mitigates the risk of an unauthorized person gaining access to the system via Secure Shell (SSH). While SSH is an industry standard to connect to posix servers, the scope of the benchmark is for Apple OSX clients, not servers.
    
    OS X does have an IP based firewall available (pf, ipfw has been deprecated) that is not enabled or configured. There are more details and links in section 7.5. OS X no longer has TCP Wrappers support built-in and does not have strong Brute-Force password guessing mitigations, or frequent patching of openssh by Apple. Most OS X computers are mobile workstations, managing IP based firewall rules on mobile devices can be very resource intensive. All of these factors can be parts of running a hardened SSH server.
  "
  impact 1.0
  describe bash("launchctl list | grep com.openssh.sshd") do
    its("stdout") { should_not match(/./) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.6_Disable_DVD_or_CD_Sharing" do
  title "Disable DVD or CD Sharing"
  desc  "
    DVD or CD Sharing allows users to remotely access the system's optical drive.
    
    Rationale: Disabling DVD or CD Sharing minimizes the risk of an attacker using the optical drive as a vector for attack and exposure of sensitive data.
  "
  impact 1.0
  describe bash("launchctl list | egrep ODSAgent") do
    its("stdout") { should_not match(/./) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.7_Disable_Bluetooth_Sharing" do
  title "Disable Bluetooth Sharing"
  desc  "
    Bluetooth Sharing allows files to be exchanged with Bluetooth enabled devices.
    
    Rationale: Disabling Bluetooth Sharing minimizes the risk of an attacker using Bluetooth to remotely attack the system.
  "
  impact 1.0
  describe bash("UUID=`ioreg -rd1 -c IOPlatformExpertDevice | grep \"IOPlatformUUID\" | sed -e 's/^.* \"\\(.*\\)\"$/\\1/'`; for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/ByHost/com.apple.Bluetooth.$UUID; if [ -e $PREF.plist ]; then echo -n \"Checking User: '$i': \"; defaults read $PREF.plist PrefKeyServicesEnabled; fi; done") do
    its("stdout") { should_not match(/\s1$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.8_Disable_File_Sharing" do
  title "Disable File Sharing"
  desc  "
    Apple's File Sharing uses a combination of SMB (Windows sharing) and AFP (Mac sharing)
    
    Three common ways to share files using File Sharing are:
    
    * Apple File Protocol (AFP)
    AFP automatically uses encrypted logins, so this method of sharing files is fairly secure. The entire hard disk is shared to administrator user accounts. Individual home folders are shared to their respective user accounts. Users' \"Public\" folders (and the \"Drop Box\" folder inside) are shared to any user account that has sharing access to the computer (i.e. anyone in the \"staff\" group, including the guest account if it is enabled).
    * Server Message Block (SMB), Common Internet File System (CIFS)
    When Windows (or possibly Linux) computers need to access file shared on a Mac, SMB/CIFS file sharing is commonly used. Apple warns that SMB sharing stores passwords is a less secure fashion than AFP sharing and anyone with system access can gain access to the password for that account. When sharing with SMB, each user that will access the Mac must have SMB enabled.
    
    Rationale: By disabling file sharing, the remote attack surface and risk of unauthorized access to files stored on the system is reduced.
  "
  impact 1.0
  describe bash("launchctl list | egrep '(nmdb|smdb|AppleFileServer)'") do
    its("stdout") { should_not match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.4.9_Disable_Remote_Management" do
  title "Disable Remote Management"
  desc  "
    Remote Management is the client portion of Apple Remote Desktop (ARD). Remote Management can be used by remote administrators to view the current Screen, install software, report on, and generally manage client Macs.
    
    The screen sharing options in Remote Management are identical to those in the Screen Sharing section. In fact, only one of the two can be configured. If Remote Management is used, refer to the Screen Sharing section above on issues regard screen sharing.
    
    Remote Management should only be enabled when a Directory is in place to manage the accounts with access. Computers will be available on port 5900 on an OS X System and could accept connections from untrusted hosts depending on the configuration, definitely a concern for mobile systems.
    
    Rationale: Remote management should only be enabled on trusted networks with strong user controls present in a Directory system. Mobile devices without strict controls are vulnerable to exploit and monitoring.
  "
  impact 1.0
  describe bash("ps -ef | egrep ARDAgent") do
    its("stdout") { should_not match(/\/System\/Library\/CoreServices\/RemoteManagement\/ARDAgent.app\/Contents\/MacOS\/ARDAgent$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.6.1_Enable_FileVault" do
  title "Enable FileVault"
  desc  "
    FileVault secures a system's data by automatically encrypting its boot volume and requiring a password or recovery key to access it.
    
    Rationale: Encrypting sensitive data minimizes the likelihood of unauthorized users gaining access to it.
  "
  impact 1.0
  describe bash("diskutil cs list | grep -i encryption") do
    its("stdout") { should match(/Encryption Status:\s+Unlocked/) }
  end
  describe bash("diskutil cs list | grep -i encryption") do
    its("stdout") { should match(/Encryption Type:\s*AES-XTS/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.6.2_Enable_Gatekeeper" do
  title "Enable Gatekeeper"
  desc  "
    Gatekeeper is Apple's application white-listing control that restricts downloaded applications from launching. It functions as a control to limit applications from unverified sources from running without authorization.
    
    Rationale: Disallowing unsigned software will reduce the risk of unauthorized or malicious applications from running on the system.
  "
  impact 1.0
  describe bash("spctl --status") do
    its("stdout") { should match(/assessments\s+enabled/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.6.3_Enable_Firewall" do
  title "Enable Firewall"
  desc  "
    A firewall is a piece of software that blocks unwanted incoming connections to a system. Apple has posted general documentation about the application firewall.
    
    [http://support.apple.com/en-us/HT201642](http://support.apple.com/en-us/HT201642)
    
    Rationale: A firewall minimizes the threat of unauthorized users from gaining access to your system while connected to a network or the Internet.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.alf globalstate ") do
    its("stdout") { should match(/1|2/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.6.4_Enable_Firewall_Stealth_Mode" do
  title "Enable Firewall Stealth Mode"
  desc  "
    While in Stealth mode the computer will not respond to unsolicited probes, dropping that traffic.
    
    [http://support.apple.com/en-us/HT201642](http://support.apple.com/en-us/HT201642)
    
    Rationale: Stealth mode on the firewall minimizes the threat of system discovery tools while connected to a network or the Internet.
  "
  impact 1.0
  describe bash("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode") do
    its("stdout") { should match(/Stealth mode enabled/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.6.5_Review_Application_Firewall_Rules" do
  title "Review Application Firewall Rules"
  desc  "
    A firewall is a piece of software that blocks unwanted incoming connections to a system. Apple has posted general documentation about the application firewall.
    
    [http://support.apple.com/en-us/HT201642](http://support.apple.com/en-us/HT201642)
    
    A computer should have a limited number of applications open to incoming connectivity. This rule will check for whether there are more than 10 rules for inbound connections.
    
    Rationale: A firewall minimizes the threat of unauthorized users from gaining access to your system while connected to a network or the Internet. Which applications are allowed access to accept incoming connections through the firewall is important to understand.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.alf globalstate ") do
    its("stdout") { should match(/1/) }
  end
  describe bash("/usr/libexec/ApplicationFirewall/socketfilterfw --listapps") do
    its("stdout") { should_not match(/^ALF: total number of apps = [1-9][0-9]+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.8.2_Time_Machine_Volumes_Are_Encrypted" do
  title "Time Machine Volumes Are Encrypted"
  desc  "
    One of the most important security tools for data protection on MacOS is FileVault. With encryption in place it makes it difficult for an outside party to access your data if they get physical possession of the computer. One very large weakness in data protection with FileVault is the level of protection on backup volumes. If the internal drive is encrypted but the external backup volume that goes home in the same laptop bag is not it is self-defeating. Apple tries to make this mistake easily avoided by providing a checkbox to enable encryption when setting-up a time machine backup. Using this option does require some password management, particularly if a large drive is used with multiple computers. A unique complex password to unlock the drive can be stored in keychains on multiple systems for ease of use.
    
    While some portable drives may contain non-sensitive data and encryption may make interoperability with other systems difficult backup volumes should be protected just like boot volumes.
    
    Rationale: Backup volumes need to be encrypted
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_2.9_Pair_the_remote_control_infrared_receiver_if_enabled" do
  title "Pair the remote control infrared receiver if enabled"
  desc  "
    An infrared receiver is a piece of hardware that sends information from an infrared remote control to another device by receiving and decoding signals. If a remote is used with a computer, a specific remote, or \"pair\", can be set-up to work with the computer. This will allow only the paired remote to work on that computer. If a remote is needed the receiver should only be accessible by a paired device. Many models do not have infrared hardware. The audit check looks for the hardware first.
    
    Rationale: An infrared remote can be used from a distance to circumvent physical security controls. A remote could also be used to page through a document or presentation, thus revealing sensitive information.
  "
  impact 1.0
  describe bash("system_profiler -detailLevel basic SPUSBDataType 2>/dev/null | egrep  \"IR Receiver\"; if [ \"$?\" == 0 ]; then ENABLED=$(defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled); UIDFILTER=$(defaults read /Library/Preferences/com.apple.driver.AppleIRController UIDFilter); if [ $ENABLED == 1 ]; then if [ \"$UIDFILTER\" == \"none\" ]; then echo Enabled and Not Paired; else echo Enabled and Paired; fi; else echo Disabled; fi; else echo Disabled; fi") do
    its("stdout") { should_not match(/Enabled and Not Paired/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.10_Enable_Secure_Keyboard_Entry_in_terminal.app" do
  title "Enable Secure Keyboard Entry in terminal.app"
  desc  "
    Secure Keyboard Entry prevents other applications on the system and/or network from detecting and recording what is typed into Terminal.
    
    Rationale: Enabling Secure Keyboard Entry minimizes the risk of a key logger from detecting what is entered in Terminal.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.Terminal; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF SecureKeyboardEntry 2>&1 | egrep '(Checking|^\\d$|not exist)'; fi; done") do
    its("stdout") { should match(/^Checking User: '.*': 1$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.1_Retain_system.log_for_90_or_more_days" do
  title "Retain system.log for 90 or more days"
  desc  "
    OSX writes information pertaining to system-related events to the file /var/log/system.log and has a configurable retention policy for this file. The default logging setting limits the file size of the logs and the maximum size for all logs with it's own rule in asl.conf. The default allows for an errant application to fill the log files and does not enforce sufficient log retention. The Benchmark recommends a value based on standard use cases. The value should align with local requirements within the organization.
    
    The default value has an \"all_max\" file limitation, no reference to a minimum retention and a less precise rotation argument.
    
    * The maximum file size limitation string should be removed \"all_max=\"
    * An organization appropriate retention should be added \"ttl=\"
    * The rotation should be set with time stamps \"rotate=utc\" or \"rotate=local\"
    
    Rationale: Archiving and retaining system.log for 90 or more days is beneficial in the event of an incident as it will allow the user to view the various changes to the system along with the date and time they occurred.
  "
  impact 1.0
  describe file("/etc/asl.conf") do
    its("content") { should match(/^> system.log [^#]* ttl=(9[0-9]|[1-9][0-9]{2,})(\s.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.2_Retain_appfirewall.log_for_90_or_more_days" do
  title "Retain appfirewall.log for 90 or more days"
  desc  "
    OSX writes information pertaining to system-related events to the file /var/log/appfirewall.log and has a configurable retention policy for this file. The default logging setting limits the file size of the logs and the maximum size for all logs with it's own rule in asl.conf. The default allows for an errant application to fill the log files and does not enforce sufficient log retention. The Benchmark recommends a value based on standard use cases. The value should align with local requirements within the organization.
    
    The default value has an \"all_max\" file limitation, no reference to a minimum retention and a less precise rotation argument.
    
    * The maximum file size limitation string should be removed \"all_max=\"
    * An organization appropriate retention should be added \"ttl=\"
    * The rotation should be set with time stamps \"rotate=utc\" or \"rotate=local\"
    
    Rationale: Archiving and retaining appfirewall.log for 90 or more days is beneficial in the event of an incident as it will allow the user to view the various changes to the system along with the date and time they occurred.
  "
  impact 1.0
  describe file("/etc/asl.conf") do
    its("content") { should match(/^>[^#]*\s+appfirewall.log\s+([^#]+\s+)?ttl=(9[0-9]|[1-9][0-9]{2,})(\s.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.3_Retain_authd.log_for_90_or_more_days" do
  title "Retain authd.log for 90 or more days"
  desc  "
    OSX writes information pertaining to system-related events to the file /var/log/authd.log and has a configurable retention policy for this file. The default logging setting limits the file size of the logs and the maximum size for all logs with it's own rule in asl.conf. The default allows for an errant application to fill the log files and does not enforce sufficient log retention. The Benchmark recommends a value based on standard use cases. The value should align with local requirements within the organization.
    
    The default value has an \"all_max\" file limitation, no reference to a minimum retention and a less precise rotation argument.
    
    * The maximum file size limitation string should be removed \"all_max=\"
    * An organization appropriate retention should be added \"ttl=\"
    * The rotation should be set with time stamps \"rotate=utc\" or \"rotate=local\"
    
    Rationale: Archiving and retaining authd.log for 90 or more days is beneficial in the event of an incident as it will allow the user to view the various changes to the system along with the date and time they occurred.
  "
  impact 1.0
  describe file("/etc/asl/com.apple.authd") do
    its("content") { should match(/^\* file \/var\/log\/authd.log [^#]* ttl=(9[0-9]|[1-9][0-9]{2,})(\s.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2_Enable_security_auditing" do
  title "Enable security auditing"
  desc  "
    OSX's audit facility, auditd, receives notifications from the kernel when certain system calls, such as open, fork, and exit, are made. These notifications are captured and written to an audit log.
    
    Rationale: Logs generated by auditd may be useful when investigating a security incident as they may help reveal the vulnerable application and the actions taken by a malicious actor.
  "
  impact 1.0
  describe bash("launchctl list | grep -i auditd ") do
    its("stdout") { should match(/com.apple.auditd/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5_Retain_install.log_for_365_or_more_days" do
  title "Retain install.log for 365 or more days"
  desc  "
    OSX writes information pertaining to system-related events to the file /var/log/install.log and has a configurable retention policy for this file. The default logging setting limits the file size of the logs and the maximum size for all logs. The default allows for an errant application to fill the log files and does not enforce sufficient log retention. The Benchmark recommends a value based on standard use cases. The value should align with local requirements within the organization.
    
    The default value has an \"all_max\" file limitation, no reference to a minimum retention and a less precise rotation argument.
    
    * The maximum file size limitation string should be removed \"all_max=\"
    * An organization appropriate retention should be added \"ttl=\"
    * The rotation should be set with time stamps \"rotate=utc\" or \"rotate=local\"
    
    Rationale: Archiving and retaining install.log for at least a year is beneficial in the event of an incident as it will allow the user to view the various changes to the system along with the date and time they occurred.
  "
  impact 1.0
  describe file("/etc/asl/com.apple.install") do
    its("content") { should match(/^\* file \/var\/log\/install.log [^#]* ttl=([1-9][0-9]{3,}|[4-9][0-9]{2}|3([7-9][0-9]|6[5-9]))(\s.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2_Enable_Show_Wi-Fi_status_in_menu_bar" do
  title "Enable \"Show Wi-Fi status in menu bar\""
  desc  "
    The Wi-Fi status in the menu bar indicates if the system's wireless internet capabilities are enabled. If so, the system will scan for available wireless networks to connect to. At the time of this revision all computers Apple builds have wireless, that has not always been the case, This control only pertains to systems that have a wireless NIC. Operating systems running in a virtual environment may not score as expected either.
    
    Rationale: Enabling \"Show Wi-Fi status in menu bar\" is a security awareness method that helps mitigate public area wireless exploits by making the user aware of their wireless connectivity status.
  "
  impact 1.0
  describe bash("networksetup -listallhardwareports | grep -i Wi-Fi && for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.systemuiserver; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF menuExtras 2>&1 | grep AirPort.menu || echo 'Not Set'; fi; done") do
    its("stdout") { should_not match(/Not Set$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4_Ensure_http_server_is_not_running" do
  title "Ensure http server is not running"
  desc  "
    Mac OS X used to have a graphical front-end to the embedded Apache web server in the Operating System. Personal web sharing could be enabled to allow someone on another computer to download files or information from the user's computer. Personal web sharing from a user endpoint has long been considered questionable and Apple has removed that capability from the GUI. Apache however is still part of the Operating System and can be easily turned on to share files and provide remote connectivity to an end user computer. Web sharing should only be done through hardened web servers and appropriate cloud services.
    
    Rationale: Web serving should not be done from a user desktop. Dedicated webservers or appropriate cloud storage should be used. Open ports make it easier to exploit the computer.
  "
  impact 1.0
  describe bash("ps -ef | grep -i httpd") do
    its("stdout") { should_not match(/\/usr\/sbin\/httpd/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5_Ensure_ftp_server_is_not_running" do
  title "Ensure ftp server is not running"
  desc  "
    Mac OS X used to have a graphical front-end to the embedded ftp server in the Operating System. Ftp sharing could be enabled to allow someone on another computer to download files or information from the user's computer. Running an Ftp server from a user endpoint has long been considered questionable and Apple has removed that capability from the GUI. The Ftp server however is still part of the Operating System and can be easily turned on to share files and provide remote connectivity to an end user computer. Ftp servers meet a specialized need to distribute files without strong authentication and should only be done through hardened servers. Cloud services or other distribution methods should be considered
    
    Rationale: Ftp servers should not be run on an end user desktop. Dedicated servers or appropriate cloud storage should be used. Open ports make it easier to exploit the computer.
  "
  impact 1.0
  describe bash("launchctl list | egrep ftp") do
    its("stdout") { should_not match(/com.apple.ftpd/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6_Ensure_nfs_server_is_not_running" do
  title "Ensure nfs server is not running"
  desc  "
    Mac OS X can act as an NFS fileserver. NFS sharing could be enabled to allow someone on another computer to mount shares and gain access to information from the user's computer. File sharing from a user endpoint has long been considered questionable and Apple has removed that capability from the GUI. NFSD is still part of the Operating System and can be easily turned on to export shares and provide remote connectivity to an end user computer.
    
    Rationale: File serving should not be done from a user desktop, dedicated servers should be used. Open ports make it easier to exploit the computer.
  "
  impact 1.0
  describe bash("ps -ef | grep -i nfsd") do
    its("stdout") { should_not match(/\/sbin\/nfsd/) }
  end
  describe bash("stat -L /etc/exports > /dev/null") do
    its("exit_status") { should_not eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.1_Secure_Home_Folders" do
  title "Secure Home Folders"
  desc  "
    By default OS X allows all valid users into the top level of every other users home folder, and restricts access to the Apple default folders within. Another user on the same system can see you have a \"Documents\" folder but cannot see inside it. This configuration does work for personal file sharing but can expose user files to standard accounts on the system.
    
    The best parallel for Enterprise environments is that everyone who has a Dropbox account can see everything that is at the top level but can't see your pictures, in the parallel with OS X they can see into every new Directory that is created because of the default permissions.
    
    Home folders should be restricted to access only by the user. Sharing should be used on dedicated servers or cloud instances that are managing access controls. Some environments may encounter problems if execute rights are removed as well as read and write. Either no access or execute only for group or others is acceptable
    
    Rationale: Allowing all users to view the top level of all networked user's home folder may not be desirable since it may lead to the revelation of sensitive information.
  "
  impact 1.0
  describe bash("find /Users -type d ! -perm -1000 -maxdepth 1 -a -perm +0066 | egrep -v \"^/Users$\" ") do
    its("stdout") { should_not match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.2_Check_System_Wide_Applications_for_appropriate_permissions" do
  title "Check System Wide Applications for appropriate permissions"
  desc  "
    Applications in the System Applications Directory (/Applications) should be world executable since that is their reason to be on the system. They should not be world writable and allow any process or user to alter them for other processes or users to then execute modified versions
    
    Rationale: Unauthorized modifications of applications could lead to  the execution of malicious code.
  "
  impact 1.0
  describe bash("find /Applications -iname \"*\\.app\" -type d -perm -2 -ls") do
    its("stdout") { should_not match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.3_Check_System_folder_for_world_writable_files" do
  title "Check System folder for world writable files"
  desc  "
    Software sometimes insists on being installed in the /System Directory and have inappropriate world writable permissions.
    
    Rationale: Folders in /System should not be world writable. The audit check excludes the \"Drop Box\" folder that is part of Apple's default user template.
  "
  impact 1.0
  describe bash("find /System -type d -perm -2 -ls") do
    its("stdout") { should match(/\s\/System\/Library\/User Template\/.+\/Public\/Drop Box$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.1_Configure_account_lockout_threshold" do
  title "Configure account lockout threshold"
  desc  "
    The account lockout threshold specifies the amount of times a user can enter an incorrect password before a lockout will occur.
    
    Ensure that a lockout threshold is part of the password policy on the computer
    
    Rationale: The account lockout feature mitigates brute-force password attacks on the system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies | grep -A 1 '<key>policyAttributeMaximumFailedAuthentications</key>' | tail -1 | cut -d'>' -f2 | cut -d '<' -f1") do
    its("stdout") { should cmp <= 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.2_Set_a_minimum_password_length" do
  title "Set a minimum password length"
  desc  "
    A minimum password length is the fewest number of characters a password can contain to meet a system's requirements.
    
    Ensure that a minimum of a 15 character password is part of the password policy on the computer.
    
    Rationale: Information systems that are not protected with strong password schemes including passwords of minimum length provide a greater opportunity for attackers to crack the password and gain access to the system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must be a minimum of (1[5-9]|[2-9][0-9]|[1-9][0-9]{2,}) characters in length<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.3_Complex_passwords_must_contain_an_Alphabetic_Character" do
  title "Complex passwords must contain an Alphabetic Character"
  desc  "
    Complex passwords contain one character from each of the following classes: English uppercase letters, English lowercase letters, Westernized Arabic numerals, and non-alphanumeric characters.
    
    Ensure that an Alphabetic character is part of the password policy on the computer
    
    Rationale: The more complex a password the more resistant it will be against persons seeking unauthorized access to a system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must have at least [1-9][0-9]* letters?<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.4_Complex_passwords_must_contain_a_Numeric_Character" do
  title "Complex passwords must contain a Numeric Character"
  desc  "
    Complex passwords contain one character from each of the following classes: English uppercase letters, English lowercase letters, Westernized Arabic numerals, and non-alphanumeric characters.
    
    Ensure that a number or numeric value is part of the password policy on the computer.
    
    Rationale: The more complex a password the more resistant it will be against persons seeking unauthorized access to a system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must have at least [1-9][0-9]* numbers?<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.5_Complex_passwords_must_contain_a_Special_Character" do
  title "Complex passwords must contain a Special Character"
  desc  "
    Complex passwords contain one character from each of the following classes: English uppercase letters, English lowercase letters, Westernized Arabic numerals, and non-alphanumeric characters. Ensure that a special character is part of the password policy on the computer
    
    Rationale: The more complex a password the more resistant it will be against persons seeking unauthorized access to a system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must have at least [1-9][0-9]* special characters?<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.6_Complex_passwords_must_uppercase_and_lowercase_letters" do
  title "Complex passwords must uppercase and lowercase letters"
  desc  "
    Complex passwords contain one character from each of the following classes: English uppercase letters, English lowercase letters, Westernized Arabic numerals, and non-alphanumeric characters.
    
    Ensure that both uppercase and lowercase letters are part of the password policy on the computer
    
    Rationale: The more complex a password the more resistant it will be against persons seeking unauthorized access to a system.
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must have both uppercase and lowercase letters<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.7_Password_Age" do
  title "Password Age"
  desc  "
    Over time passwords can be captured by third parties through mistakes, phishing attacks, third party breaches or merely brute force attacks. To reduce the risk of exposure and to decrease the incentives of password reuse (passwords that are not forced to be changed periodically generally are not ever changed) users must reset passwords periodically. This control uses 90 days as the acceptable value, some organizations may be more or less restrictive. Ensure that password rotation is part of the password policy on the computer.
    
    Rationale: Passwords should be changed periodically to reduce exposure
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>policyAttributeCurrentTime &gt; policyAttributeLastPasswordChangeTime \+ policyAttributeExpiresEveryNDays \* 24 \* 60 \* 60<\/string>/) }
  end
  describe bash("pwpolicy -getaccountpolicies | grep -A 1 '<key>policyAttributeExpiresEveryNDays</key>' | tail -1 | cut -d'>' -f2 | cut -d '<' -f1") do
    its("stdout") { should cmp <= 90 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.8_Password_History" do
  title "Password History"
  desc  "
    Over time passwords can be captured by third parties through mistakes, phishing attacks, third party breaches or merely brute force attacks. To reduce the risk of exposure and to decrease the incentives of password reuse (passwords that are not forced to be changed periodically generally are not ever changed) users must reset passwords periodically. This control ensures that previous passwords are not reused immediately by keeping a history of previous passwords hashes. Ensure that password history checks are part of the password policy on the computer. This control checks whether a new password is different than the previous 15.
    
    Rationale: Old passwords should not be reused
  "
  impact 1.0
  describe bash("pwpolicy -getaccountpolicies") do
    its("stdout") { should match(/<string>Password must differ from past 15 passwords<\/string>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3_Reduce_the_sudo_timeout_period" do
  title "Reduce the sudo timeout period"
  desc  "
    The sudo command allows the user to run programs as the root user. Working as the root user allows the user an extremely high level of configurability within the system.
    
    Rationale: The sudo command stays logged in as the root user for five minutes before timing out and re-requesting a password. This five minute window should be eliminated since it leaves the system extremely vulnerable. This is especially true if an exploit were to gain access to the system, since they would be able to make changes as a root user.
  "
  impact 1.0
  describe file("/etc/sudoers") do
    its("content") { should match(/^Defaults\s+timestamp_timeout\s*=\s*0$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.7_Do_not_enable_the_root_account" do
  title "Do not enable the \"root\" account"
  desc  "
    The root account is a superuser account that has access privileges to perform any actions and read/write to any file on the computer. In the UNIX/Linux world, the system administrator commonly uses the root account to perform administrative functions.
    
    Rationale: Enabling and using the root account puts the system at risk since any successful exploit or mistake while the root account is in use could have unlimited access privileges within the system. Using the sudo command allows users to perform functions as a root user while limiting and password protecting the access privileges.  By default the root account is not enabled on a Mac OS X client computer. It is enabled on Mac OS X Server. An administrator can escalate privileges using the sudo command (use -s or -i to get a root shell).
  "
  impact 1.0
  describe bash("dscl . -read /Users/root AuthenticationAuthority 2>&1") do
    its("stdout") { should eq "No such key: AuthenticationAuthority" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.8_Disable_automatic_login" do
  title "Disable automatic login"
  desc  "
    The automatic login feature saves a user's system access credentials and bypasses the login screen, instead the system automatically loads to the user's desktop screen.
    
    Rationale: Disabling automatic login decreases the likelihood of an unauthorized person gaining access to a system.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser") do
    its("stdout") { should_not match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.9_Require_a_password_to_wake_the_computer_from_sleep_or_screen_saver" do
  title "Require a password to wake the computer from sleep or screen saver"
  desc  "
    Sleep and screensaver modes are low power modes that reduces electrical consumption while the system is not in use.
    
    Rationale: Prompting for a password when waking from sleep or screensaver mode mitigates the threat of an unauthorized person gaining access to a system in the user's absence.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.screensaver; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF askForPassword 2>&1 | egrep '(Checking|^\\d$|not exist)'; fi; done ") do
    its("stdout") { should match(/^Checking User: '.+': 1$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.10_Require_an_administrator_password_to_access_system-wide_preferences" do
  title "Require an administrator password to access system-wide preferences"
  desc  "
    System Preferences controls system and user settings on an OS X Computer. System Preferences allows the user to tailor their experience on the computer as well as allowing the System Administrator to configure global security settings. Some of the settings should only be altered by the person responsible for the computer.
    
    Rationale: By requiring a password to unlock System-wide System Preferences the risk is mitigated of a user changing configurations that affect the entire system and requires an admin user to re-authenticate to make changes
  "
  impact 1.0
  describe bash("security authorizationdb read system.preferences | grep \"<key>shared</key>\" -A1 ") do
    its("stdout") { should match(/<false\/>/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.11_Disable_ability_to_login_to_another_users_active_and_locked_session" do
  title "Disable ability to login to another user's active and locked session"
  desc  "
    OSX has a privilege that can be granted to any user that will allow that user to unlock active user's sessions.
    
    Rationale: Disabling the admins and/or user's ability to log into another user's active and locked session prevents unauthorized persons from viewing potentially sensitive and/or personal information.
  "
  impact 1.0
  describe bash("grep -i \"^account.*group=admin,wheel fail_safe\" /etc/pam.d/screensaver") do
    its("stdout") { should_not match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.12_Create_a_custom_message_for_the_Login_Screen" do
  title "Create a custom message for the Login Screen"
  desc  "
    An access warning informs the user that the system is reserved for authorized use only, and that the use of the system may be monitored.
    
    Rationale: An access warning may reduce a casual attacker's tendency to target the system. Access warnings may also aid in the prosecution of an attacker by evincing the attacker's knowledge of the system's private status, acceptable use policy, and authorization requirements.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.loginwindow.plist ") do
    its("stdout") { should match(/LoginwindowText/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.14_Do_not_enter_a_password-related_hint" do
  title "Do not enter a password-related hint"
  desc  "
    Password hints help the user recall their passwords for various systems and/or accounts. In most cases, password hints are simple and closely related to the user's password.
    
    Rationale: Password hints that are closely related to the user's password are a security vulnerability, especially in the social media age. Unauthorized users are more likely to guess a user's password if there is a password hint. The password hint is very susceptible to social engineering attacks and information exposure on social media networks
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.18_System_Integrity_Protection_status" do
  title "System Integrity Protection status"
  desc  "
    System Integrity Protection is a new security feature introduced in OS X 10.11 El Capitan. System Integrity Protection restricts access to System domain locations and restricts runtime attachment to system processes. Any attempt to attempt to inspect or attach to a system process will fail. Kernel Extensions are now restricted to /Library/Extensions and are required to be signed with a Developer ID.
    
    Rationale: Running without System Integrity Protection on a production system runs the risk of the modification of system binaries or code injection of system processes that would otherwise be protected by SIP.
  "
  impact 1.0
  describe bash("/usr/bin/csrutil status") do
    its("stdout") { should match(/^System Integrity Protection status:\s+enabled\.$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.1_Display_login_window_as_name_and_password" do
  title "Display login window as name and password"
  desc  "
    The login window prompts a user for his/her credentials, verifies their authorization level and then allows or denies the user access to the system.
    
    Rationale: Prompting the user to enter both their username and password makes it twice as hard for unauthorized users to gain access to the system since they must discover two attributes.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME") do
    its("stdout") { should eq "1" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.2_Disable_Show_password_hints" do
  title "Disable \"Show password hints\""
  desc  "
    Password hints are user created text displayed when an incorrect password is used for an account.
    
    Rationale: Password hints make it easier for unauthorized persons to gain access to systems by providing information to anyone that the user provided to assist remembering the password. This info could include the password itself or other information that might be readily discerned with basic knowledge of the end user.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint ") do
    its("stdout") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.3_Disable_guest_account_login" do
  title "Disable guest account login"
  desc  "
    The guest account allows users access to the system without having to create an account or password. Guest users are unable to make setting changes, cannot remotely login to the system and all created files, caches, and passwords are deleted upon logging out.
    
    Rationale: Disabling the guest account mitigates the risk of an untrusted user doing basic reconnaissance and possibly using privilege escalation attacks to take control of the system.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.loginwindow.plist") do
    its("stdout") { should_not match(/GuestEnabled\s*=\s*1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.4_Disable_Allow_guests_to_connect_to_shared_folders" do
  title "Disable \"Allow guests to connect to shared folders\""
  desc  "
    Allowing guests to connect to shared folders enables users to access selected shared folders and their contents from different computers on a network.
    
    Rationale: Not allowing guests to connect to shared folders mitigates the risk of an untrusted user doing basic reconnaissance and possibly use privilege escalation attacks to take control of the system.
  "
  impact 1.0
  describe bash("defaults read /Library/Preferences/com.apple.AppleFileServer") do
    its("stdout") { should_not match(/guestAccess\s*=\s*1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.5_Remove_Guest_home_folder" do
  title "Remove Guest home folder"
  desc  "
    In the previous two controls the guest account login has been disabled and sharing to guests has been disabled as well. There is no need for the legacy Guest home folder to remain in the file system. When normal user accounts are removed you have the option to archive it, leave it in place or delete. In the case of the guest folder the folder remains in place without a GUI option to remove it. If at some point in the future a Guest account is needed it will be re-created. The presence of the Guest home folder can cause automated audits to fail when looking for compliant settings within all User folders as well. Rather than ignoring the folders continued existence it is best removed.
    
    Rationale: The Guest home folders are unneeded after the Guest account is disabled and could be used inappropriately.
  "
  impact 1.0
  describe bash("ls /Users/ | grep Guest") do
    its("stdout") { should match(/.+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2_Turn_on_filename_extensions" do
  title "Turn on filename extensions"
  desc  "
    A filename extension is a suffix added to a base filename that indicates the base filename's file format.
    
    Rationale: Visible filename extensions allows the user to identify the file type and the application it is associated with which leads to quick identification of misrepresented malicious files.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/.GlobalPreferences; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF AppleShowAllExtensions 2>&1 | egrep '(^\\d$|not exist)'; fi; done") do
    its("stdout") { should match(/1$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3_Disable_the_automatic_run_of_safe_files_in_Safari" do
  title "Disable the automatic run of safe files in Safari"
  desc  "
    Safari will automatically run or execute what it considers safe files. This can include installers and other files that execute on the operating system. Safari bases file safety by using a list of filetypes maintained by Apple. The list of files include text, image, video and archive formats that would be run in the context of the OS rather than the browser.
    
    Rationale: Hackers have taken advantage of this setting via drive-by attacks. These attacks occur when a user visits a legitimate website that has been corrupted. The user unknowingly downloads a malicious file either by closing an infected pop-up or hovering over a malicious banner. An attacker can create a malicious file that will fall within Safari's safe file list that will download and execute without user input.
  "
  impact 1.0
  describe bash("for i in $(find /Users -type d -maxdepth 1); do PREF=$i/Library/Preferences/com.apple.Safari; if [ -e $PREF.plist ]; then /bin/echo -n \"Checking User: '$i': \"; defaults read $PREF AutoOpenSafeDownloads 2>&1 | egrep '(^\\d$|not exist)'; fi; done ") do
    its("stdout") { should match(/0$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.6_Automatic_Actions_for_Optical_Media" do
  title "Automatic Actions for Optical Media"
  desc  "Managing automatic actions, while useful in very few situations, is unlikely to increase security on the computer and does complicate the users experience and add additional complexity to the configuration. These settings are user controlled and can be changed without Administrator privileges unless controlled through MCX settings or Parental Controls. Unlike Windows Auto-run the optical media is accessed through Operating System applications, those same applications can open and access the media directly. If optical media is not allowed in the environment the optical media drive should be disabled in hardware and software"
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_7.10_Repairing_permissions_is_no_longer_needed_with_10.11" do
  title "Repairing permissions is no longer needed with 10.11"
  desc  "
    With the introduction of System Integrity Protection (SIP) Apple has removed the necessity of repairing permissions. In earlier versions of the Operating System repair permissions checked the receipt files of installed software and ensured that the existing permissions in the file system matched what the receipts said it should. System integrity protection manages and blocks permission to  certain directories continuously.
    
    [About OS X 10.11 #x2018;El Capitan#x2019; and Permissions Fixes](http://www.macissues.com/2015/10/02/about-os-x-10-11-el-capitan-and-permissions-fixes/)
    
    [System Integrity Protection](https://en.wikipedia.org/wiki/System_Integrity_Protection)
    
    [Sorry, Unix fans: OS X El Capitan kills root](http://www.infoworld.com/article/2988096/mac-os-x/sorry-unix-fans-os-x-el-capitan-kills-root.html)
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_8.1_Password_Policy_Plist_generated_through_OS_X_Server" do
  title "Password Policy Plist generated through OS X Server"
  desc  "
    bash-3.2# pwpolicy -getaccountpolicies
    Getting global account policies
    
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    
    !DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"&gt;
    
    <plist version=\"1.0\">
    <dict>
    <key>policyCategoryAuthentication</key>
    <array>
    <dict>
    <key>policyContent</key>
    <string>(policyAttributeFailedAuthentications  policyAttributeMaximumFailedAuthentications) or (policyAttributeCurrentTime  policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds)</string>
    <key>policyIdentifier</key>
    <string>com.apple.maximumFailedLoginAttempts</string>
    <key>policyParameters</key>
    <dict>
    <key>autoEnableInSeconds</key>
    <integer>60</integer>
    <key>policyAttributeMaximumFailedAuthentications</key>
    <integer>5</integer>
    </dict>
    </dict>
    </array>
    <key>policyCategoryPasswordChange</key>
    <array>
    <dict>
    <key>policyContent</key>
    <string>policyAttributeCurrentTime  policyAttributeLastPasswordChangeTime + policyAttributeExpiresEveryNDays * 24 * 60 * 60</string>
    <key>policyIdentifier</key>
    <string>com.apple.changeEveryNDays</string>
    <key>policyParameters</key>
    <dict>
    <key>policyAttributeExpiresEveryNDays</key>
    <integer>60</integer>
    </dict>
    </dict>
    </array>
    <key>policyCategoryPasswordContent</key>
    <array>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '.{15,}+'</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss mindestens 15 Zeichen lang sein</string>
    <key>default</key>
    <string>Password must be a minimum of 15 characters in length</string>
    <key>en</key>
    <string>Password must be a minimum of 15 characters in length</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe tener como m#x00ED;nimo 15 caracteres</string>
    <key>fr</key>
    <string>Le mot de passe doit contenir au moins 15 caract#x00E8;res</string>
    <key>it</key>
    <string>La password deve contenere almeno 15 caratteri</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306F;&#x534A;&#x89D2;&#x82F1;&#x6570;&#x5B57;&#x3067; 15 &#x6587;&#x5B57;&#x4EE5;&#x4E0A;&#x3067;&#x306A;&#x3051;&#x308C;&#x3070;&#x306A;&#x308A;&#x307E;&#x305B;&#x3093;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xCD5C;&#xC18C; 15&#xC790; &#xC774;&#xC0C1;&#xC774;&#xC5B4;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord moet minimaal 15 tekens lang zijn</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x957F;&#x5EA6;&#x5FC5;&#x987B;&#x81F3;&#x5C11;&#x4E3A; 15 &#x4E2A;&#x5B57;&#x7B26;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x7684;&#x9577;&#x5EA6;&#x6700;&#x5C11;&#x5FC5;&#x9808;&#x70BA; 15 &#x500B;&#x5B57;&#x5143;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.minimumPasswordLength</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumPasswordLength</key>
    <integer>15</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[A-Z].*[a-z].*)|(.*[a-z].*[A-Z].*)'</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss sowohl Gro#x00DF;- als auch Kleinbuchstaben enthalten</string>
    <key>default</key>
    <string>Password must have both uppercase and lowercase letters</string>
    <key>en</key>
    <string>Password must have both uppercase and lowercase letters</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe tener letras may#x00DA;sculas y min#x00DA;sculas</string>
    <key>fr</key>
    <string>Le mot de passe doit contenir des majuscules et des minuscules</string>
    <key>it</key>
    <string>La password deve contenere lettere maiuscole e minuscole</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306B;&#x306F;&#x5927;&#x6587;&#x5B57;&#x3068;&#x5C0F;&#x6587;&#x5B57;&#x306E;&#x4E21;&#x65B9;&#x3092;&#x542B;&#x3081;&#x308B;&#x5FC5;&#x8981;&#x304C;&#x3042;&#x308A;&#x307E;&#x3059;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xB300;&#xBB38;&#xC790; &#xBC0F; &#xC18C;&#xBB38;&#xC790;&#xB97C; &#xBAA8;&#xB450; &#xD3EC;&#xD568;&#xD574;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord moet hoofdetters en kleine letters bevatten</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x5305;&#x542B;&#x5927;&#x5199;&#x5B57;&#x6BCD;&#x548C;&#x5C0F;&#x5199;&#x5B57;&#x6BCD;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x5FC5;&#x9808;&#x6709;&#x5927;&#x5BEB;&#x53CA;&#x5C0F;&#x5BEB;&#x5B57;&#x6BCD;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.uppercaseAndLowercase</string>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[A-Za-z].*){1,}'</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss mindestens 1 Buchstaben enthalten</string>
    <key>default</key>
    <string>Password must have at least 1 letter</string>
    <key>en</key>
    <string>Password must have at least 1 letter</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe tener como m#x00ED;nimo 1 letra</string>
    <key>fr</key>
    <string>Le mot de passe doit contenir au moins 1 lettre</string>
    <key>it</key>
    <string>La password deve contenere almeno 1 lettera</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306B;&#x306F; 1 &#x6587;&#x5B57;&#x4EE5;&#x4E0A;&#x306E;&#x82F1;&#x5B57;&#x3092;&#x542B;&#x3081;&#x308B;&#x5FC5;&#x8981;&#x304C;&#x3042;&#x308A;&#x307E;&#x3059;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xCD5C;&#xC18C; 1&#xC790;&#xC758; &#xBB38;&#xC790;&#xB97C; &#xD3EC;&#xD568;&#xD574;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord moet minimaal 1 letter bevatten</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x5305;&#x542B;&#x81F3;&#x5C11; 1 &#x4E2A;&#x5B57;&#x6BCD;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x81F3;&#x5C11;&#x5FC5;&#x9808;&#x6709; 1 &#x500B;&#x5B57;&#x6BCD;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.minimumLetters</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumLetters</key>
    <integer>1</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[0-9].*){1,}'</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss mindestens 1 Ziffer enthalten</string>
    <key>default</key>
    <string>Password must have at least 1 number</string>
    <key>en</key>
    <string>Password must have at least 1 number</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe tener como m#x00ED;nimo 1 n#x00DA;mero</string>
    <key>fr</key>
    <string>Le mot de passe doit contenir au moins 1 chiffre</string>
    <key>it</key>
    <string>La password deve contenere almeno 1 numero</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306B;&#x306F; 1 &#x500B;&#x4EE5;&#x4E0A;&#x306E;&#x6570;&#x5B57;&#x3092;&#x542B;&#x3081;&#x308B;&#x5FC5;&#x8981;&#x304C;&#x3042;&#x308A;&#x307E;&#x3059;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xCD5C;&#xC18C; 1&#xC790;&#xC758; &#xC22B;&#xC790;&#xB97C; &#xD3EC;&#xD568;&#xD574;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord moet minimaal 1 cijfer bevatten</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x5305;&#x542B;&#x81F3;&#x5C11; 1 &#x4E2A;&#x6570;&#x5B57;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x81F3;&#x5C11;&#x5FC5;&#x9808;&#x6709; 1 &#x500B;&#x6578;&#x5B57;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.minimumNumerics</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumNumerics</key>
    <integer>1</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[^A-Za-z0-9].*){1,}'</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss mindestens 1 Sonderzeichen enthalten</string>
    <key>default</key>
    <string>Password must have at least 1 special character</string>
    <key>en</key>
    <string>Password must have at least 1 special character</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe tener como m#x00ED;nimo 1 car#x00E1;cter especial</string>
    <key>fr</key>
    <string>Le mot de passe doit contenir au moins 1 caract#x00E8;re sp#x00E9;cial</string>
    <key>it</key>
    <string>La password deve contenere almeno 1 carattere speciale</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306B;&#x306F; 1 &#x500B;&#x4EE5;&#x4E0A;&#x306E;&#x7279;&#x6B8A;&#x6587;&#x5B57;&#x3092;&#x542B;&#x3081;&#x308B;&#x5FC5;&#x8981;&#x304C;&#x3042;&#x308A;&#x307E;&#x3059;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xCD5C;&#xC18C; 1&#xC790;&#xC758; &#xD2B9;&#xC218; &#xBB38;&#xC790;&#xB97C; &#xD3EC;&#xD568;&#xD574;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord moet minimaal 1 speciaal teken bevatten</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x5305;&#x542B;&#x81F3;&#x5C11; 1 &#x4E2A;&#x7279;&#x6B8A;&#x5B57;&#x7B26;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x81F3;&#x5C11;&#x5FC5;&#x9808;&#x6709; 1 &#x500B;&#x7279;&#x6B8A;&#x5B57;&#x5143;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.minimumSpecialCharacters</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumSpecialCharacters</key>
    <integer>1</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword != policyAttributeRecordName</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss sich vom Accountnamen unterscheiden</string>
    <key>default</key>
    <string>Password must differ from account name</string>
    <key>en</key>
    <string>Password must differ from account name</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe ser diferente del nombre de la cuenta</string>
    <key>fr</key>
    <string>Le mot de passe doit #x00EA;tre diff#x00E9;rent du nom du compte</string>
    <key>it</key>
    <string>La password deve essere diversa dal nome dell'account</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x3092;&#x30A2;&#x30AB;&#x30A6;&#x30F3;&#x30C8;&#x540D;&#x3068;&#x540C;&#x3058;&#x306B;&#x306F;&#x3067;&#x304D;&#x307E;&#x305B;&#x3093;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xACC4;&#xC815; &#xC774;&#xB984;&#xACFC; &#xB2EC;&#xB77C;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord mag niet hetzelfde zijn als de accountnaam</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x4E0E;&#x5E10;&#x6237;&#x540D;&#x79F0;&#x4E0D;&#x540C;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x5FC5;&#x9808;&#x4E0D;&#x540C;&#x65BC;&#x5E33;&#x865F;&#x540D;&#x7A31;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.passwordDiffersFromName</string>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
    <key>policyContentDescription</key>
    <dict>
    <key>de</key>
    <string>Das Passwort muss sich von den letzten 15 Passw#x00D6;rtern unterscheiden</string>
    <key>default</key>
    <string>Password must differ from past 15 passwords</string>
    <key>en</key>
    <string>Password must differ from past 15 passwords</string>
    <key>es</key>
    <string>La contrase#x00D1;a debe ser diferente de las #x00DA;ltimas 15 contrase#x00D1;as</string>
    <key>fr</key>
    <string>Le mot de passe doit #x00EA;tre diff#x00E9;rent des 15 derniers mots de passe</string>
    <key>it</key>
    <string>La password deve essere diversa dalle ultime 15 password</string>
    <key>ja</key>
    <string>&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x306F;&#x904E;&#x53BB;&#x306B;&#x4F7F;&#x7528;&#x3057;&#x305F; 15 &#x500B;&#x306E;&#x30D1;&#x30B9;&#x30EF;&#x30FC;&#x30C9;&#x3068;&#x540C;&#x3058;&#x306B;&#x306F;&#x3067;&#x304D;&#x307E;&#x305B;&#x3093;</string>
    <key>ko</key>
    <string>&#xC554;&#xD638;&#xB294; &#xC774;&#xC804; 15 &#xC554;&#xD638;&#xC640; &#xB2EC;&#xB77C;&#xC57C; &#xD569;&#xB2C8;&#xB2E4;.</string>
    <key>nl</key>
    <string>Het wachtwoord mag niet hetzelfde zijn als de vorige 15 wachtwoorden</string>
    <key>zh-Hans</key>
    <string>&#x5BC6;&#x7801;&#x5FC5;&#x987B;&#x4E0E;&#x4E4B;&#x524D;&#x7684; 15 &#x4E2A;&#x5BC6;&#x7801;&#x4E0D;&#x540C;</string>
    <key>zh-Hant</key>
    <string>&#x5BC6;&#x78BC;&#x5FC5;&#x9808;&#x4E0D;&#x540C;&#x65BC;&#x524D; 15 &#x7D44;&#x5BC6;&#x78BC;</string>
    </dict>
    <key>policyIdentifier</key>
    <string>com.apple.passwordDiffersFromPastNPasswords</string>
    <key>policyParameters</key>
    <dict>
    <key>policyAttributePasswordHistoryDepth</key>
    <integer>15</integer>
    </dict>
    </dict>
    </array>
    </dict>
    </plist>
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_8.2_Password_Policy_Plist_from_man_page" do
  title "Password Policy Plist from man page"
  desc  "
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    
    !DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"&gt;
    
    <plist version=\"1.0\">
    <dict>
    <key>policyCategoryAuthentication</key>
    <array>
    <dict>
    <key>policyContent</key>
    <string>policyAttributeFailedAuthentications  policyAttributeMaximumFailedAuthentications</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.maxFailedLoginAttempts</string>
    <key>policyParameters</key>
    <dict>
    <key>policyAttributeMaximumFailedAuthentications</key>
    <integer>5</integer>
    </dict>
    </dict>
     <key>policyCategoryPasswordContent</key>
    <string>policyAttributePassword matches #x2018;.{15,}+#x2019;</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.minChars</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumLength</key>
    <integer>15</integer>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches #x2018;.{15,}+#x2019;</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.minChars</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumLength</key>
    <integer>15</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[a-zA-Z].*){1,}+'</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.requiresAlpha</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumAlphaCharacters</key>
    <integer>1</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.requiresNumeric</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumNumericCharacters</key>
    <integer>1</integer>
    </dict>
    </dict>
    <dict>
    <key>policyContent</key>
    <string>policyAttributePassword matches '(.*[`~!@\#$%^*()_+-={}|\\[\\]\\\\:\";'?,./].*){1,}+'</string>
    <key>policyIdentifier</key>
    <string>com.apple.policy.legacy.requiresSymbol</string>
    <key>policyParameters</key>
    <dict>
    <key>minimumSymbolCharacters</key>
    <integer>1</integer>
    </dict>
    </dict>
    </array>
    </dict>
    </plist>
  "
  impact 0.0
end