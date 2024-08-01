# install-sysmon

Install Sysmon on target machine with some obfuscation techniques

## Resources

- [Detecting Sysmon on the Victim Host](https://www.ired.team/offensive-security/enumeration-and-discovery/detecting-sysmon-on-the-victim-host#get-sysmonconfiguration)
- [Sysmon hide and seek](https://www.bussink.net/sysmon-hide-and-seek/)
- [RegistryRights Enum](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryrights?view=netframework-4.8)
- [TrustedSec - Sysmon Install and Configuration](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/install_windows.md#command-line-parameters)

## Details

This role install sysmon on the target machine and apply the following obfuscation mechanisms:

- Modifies the Sysmon executable name
- Modifies the Sysmon driver name
- Modifies the Sysmon service description
- Modifies the Sysmon driver instance name
- Modifies the Sysmon driver altitude (read this before assign an altitude: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes)

And applies the following SACL Audit rules to the following FileSystem and Registry items:

- Sysmon config filename
- HKCU:\Software\Sysinternals\System Monitor
- HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
- "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{{sysmon_obfuscated_drivername}}\\Instances\\Sysmon Instance"

When a preceding Secureble Object have been opened by a process, the `4663` EventId code will be fired.

To generates these events, the below audit role must be enabled from the `Local Group Policy Editor`:

- Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\System Audit Policies - Local Group Policy Object\Object Access\Audit File System
- Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\System Audit Policies - Local Group Policy Object\Object Access\Audit Registry

## Example Playbook

```yaml
  - name: Install obfuscated sysmon
      import_role:
        name: install-sysmon
      vars:
        sysmon_obfuscated_filename: "abc"
        sysmon_obfuscated_drivername: "abcdrv"
        sysmon_obfuscated_description: "Sample Description"
        sysmon_obfuscated_driver_altitude: 371234
        sysmon_config_filename: "sysmonconfig-export.xml"
```
