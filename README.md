# mimipenguin
A tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz. 

![alt text](http://i.imgur.com/BkDX9dF.png "MimiPenguin")

## Details
Takes advantage of cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords. Will attempt to calculate each word's probability by checking hashes in /etc/shadow, hashes in memory, and regex searches.

## Requires
* root permissions

## Supported/Tested
* Kali 4.3.0 (rolling) x64 (gdm3)
* Ubuntu Desktop 12.04 LTS x64 (Gnome Keyring 3.18.3-0ubuntu2)
* Ubuntu Desktop 16.04 LTS x64 (Gnome Keyring 3.18.3-0ubuntu2)
* XUbuntu Desktop 16.04 x64 (Gnome Keyring 3.18.3-0ubuntu2)
* VSFTPd 3.0.3-8+b1 (Active FTP client connections)
* Apache2 2.4.25-3 (Active/Old HTTP BASIC AUTH Sessions) [Gcore dependency]
* openssh-server 1:7.3p1-1 (Active SSH connections - sudo usage)

## Notes
* Password moves in memory - still honing in on 100% effectiveness
* Plan on expanding support and other credential locations
* Working on expanding to non-desktop environments
* Known bug - sometimes gcore hangs the script, this is a problem with gcore
* Open to pull requests and community research
* LDAP research (nscld winbind etc) planned for future

## Contact
* Twitter: [@huntergregal](https://twitter.com/HunterGregal)
* Website: [huntergregal.com](http://huntergregal.com)
* Github: [huntergregal](https://github.com/huntergregal)

## Licence
CC BY 4.0 licence - https://creativecommons.org/licenses/by/4.0/

## Special Thanks 
* the-useless-one for remove Gcore as a dependency, cleaning up tabs, and adding output option
* gentilkiki for Mimikatz, the inspiration and the twitter shoutout
* pugilist for cleaning up PID extraction and testing
* ianmiell for cleaning up some of my messy code
* w0rm for identifying printf error when special chars are involved
* benichmt1 for identifying multiple authenticate users issue
* ChaitanyaHaritash for identifying special char edge case issues
* ImAWizardLizard for cleaning up the pattern matches with a for loop
