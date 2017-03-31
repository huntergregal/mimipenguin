# mimipenguin
A tool to dump the login password from the current linux desktop user. Adapted after the idea behind the popular Windows tool mimikatz. 
* Special thanks to pugilist for cleaning up PID extraction and testing.

# Details
Takes advantage of the gnome login screen feature by dumping the memory of the process and extracting lines that have a high probability of containing the current user's cleartext password. Will attempt to calculate each word's probability by checking hashes in /etc/shadow.
Added support for VSFTPD, Apache2 HTTP Basic Auth

# Requires
* root permissions

# Supported/Tested
* Kali 4.3.0 (rolling) x64 (Gnome Desktop)
* Ubuntu Desktop 12.04 LTS x64 (Gnome Desktop)
* Ubuntu Desktop 16.04 LTS x64 (Gnome Desktop)
* VSFTPd 3.0.3-8+b1 (Active FTP client connections)
* Apache2 2.4.25-3 (Active/Old HTTP BASIC AUTH Sessions)

# Notes
* Password moves in memory - still honing in on 100% effectiveness
* Plan on expanding support and other credential locations
* Working on expanding to non-desktop environments
* Known bug - sometimes gcore hangs the script, this is a problem with gcore

