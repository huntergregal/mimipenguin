# mimipenguin
A tool to dump the login password from the current linux user. Adapted after the idea behind the popular Windows tool mimikatz. 
* Special thanks to pugilist for cleaning up PID extraction and testing.

# Details
Takes advantage of the gnome login screen feature by dumping the memory of the process and extracting lines that have a high probability of containing the current user's cleartext password.

# Supported/Tested
* Kali 4.3.0 (rolling) x64
* Ubuntu 12.04 LTS x64

# Notes
* Ubuntu support still in testing
* Plan on expanding support and other credential locations

