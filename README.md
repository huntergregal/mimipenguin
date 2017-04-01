# mimipenguin
A tool to dump the login password from the current linux desktop user. Adapted after the idea behind the popular Windows tool mimikatz. 
* Special thanks to pugilist for cleaning up PID extraction and testing.

![alt text](http://i.imgur.com/BkDX9dF.png "MimiPenguin")

## Details
Takes advantage of cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords. Will attempt to calculate each word's probability by checking hashes in /etc/shadow, hashes in memory, and regex searches.

## Requires
* root permissions

## Supported/Tested
* Kali 4.3.0 (rolling) x64 (Gnome Desktop)
* Ubuntu Desktop 12.04 LTS x64 (Gnome Desktop)
* Ubuntu Desktop 16.04 LTS x64 (Gnome Desktop)
* VSFTPd 3.0.3-8+b1 (Active FTP client connections)
* Apache2 2.4.25-3 (Active/Old HTTP BASIC AUTH Sessions)
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
