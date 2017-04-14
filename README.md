# mimipenguin
A tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz. 

![alt text](http://i.imgur.com/BkDX9dF.png "MimiPenguin")

## Details
Takes advantage of cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords. Will attempt to calculate each word's probability by checking hashes in /etc/shadow, hashes in memory, and regex searches.

## Requires
* root permissions

## Supported/Tested Systems
* Kali 4.3.0 (rolling) x64 (gdm3)
* Ubuntu Desktop 12.04 LTS x64 (Gnome Keyring 3.18.3-0ubuntu2)
* Ubuntu Desktop 16.04 LTS x64 (Gnome Keyring 3.18.3-0ubuntu2)
* XUbuntu Desktop 16.04 x64 (Gnome Keyring 3.18.3-0ubuntu2)
* Archlinux x64 Gnome 3 (Gnome Keyring 3.20)
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

## Development Roadmap
MimiPenguin is slowly being ported to multiple languages to support all possible post-exploit scenarios. The roadmap below was suggested by KINGSABRI to track the various versions and features. An "X" denotes full support while a "~" denotes a feature with known bugs.

| Feature                                    | .sh | .py |
|--------------------------------------------|-----|-----|
| Kali Desktop Password (gdm3)               | X   | X   |
| Ubuntu Desktop Password (Gnome Keyring)    | X   | X   |
| Arch Desktop Password (Gnome Keyring)      | X   |     |
| VSFTPd (Active FTP Connections)            | X   | X   |
| Apache2 (Active HTTP Basic Auth Sessions)  | ~   | ~   |
| OpenSSH (Active SSH Sessions - Sudo Usage) | ~   | ~   |

## Contact
* Twitter: [@huntergregal](https://twitter.com/HunterGregal)
* Website: [huntergregal.com](http://huntergregal.com)
* Github: [huntergregal](https://github.com/huntergregal)

## Licence
CC BY 4.0 licence - https://creativecommons.org/licenses/by/4.0/

## Special Thanks 
* the-useless-one for remove Gcore as a dependency, cleaning up tabs, adding output option, and a full python3 port
* gentilkiwi for Mimikatz, the inspiration and the twitter shoutout
* pugilist for cleaning up PID extraction and testing
* ianmiell for cleaning up some of my messy code
* w0rm for identifying printf error when special chars are involved
* benichmt1 for identifying multiple authenticate users issue
* ChaitanyaHaritash for identifying special char edge case issues
* ImAWizardLizard for cleaning up the pattern matches with a for loop
* coreb1t for python3 checks, arch support, other fixes
* n1nj4sec for a python2 port and support
* KINGSABRI for the Roadmap proposal
