# Mimipenguin beta-2.0
A tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz. 

![alt text](https://i.imgur.com/pwP8vRh.png "MimiPenguin")

## Details
This version of Mimipenguin sacrifices features and coverage (as opposed to the beta-1.0 py and sh scripts) in favor of speed and efficiency. Beta 2.0 uses hardcoded offsets for known structures in memory along with PTRACE to reliably extract cleartext user passwords from linux desktop environments.

## Requires
* root permissions
* a supported target

## Supported
| OS                           |   Service                        | Supprted          |
|------------------------------|----------------------------------|-------------------|
| Ubuntu Desktop 12.04 LTS x64 | gnome-keyring-daemon (3.18.3)    | :heavy_check_mark: |
| Ubuntu Desktop 16.04 LTS x64 | gnome-keyring-daemon (3.18.3)    | :heavy_check_mark: |
| Kali-rolling x64             | gnome-keyring-daemon (3.28.0.2)  | :heavy_check_mark: |

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
* bourgouinadrien for linking https://github.com/koalaman/shellcheck
* bcoles for adding more needles and work on a metasploit module ruby port
