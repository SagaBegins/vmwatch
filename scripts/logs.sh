#!/bin/bash

while [[ $# -gt 0 ]]
do
	case $1 in
	-h|--help) 
		echo "Usage: ./logs.sh <prefix>"
		echo "logs ps, netstat and lsmod into <prefix>_command.txt"
		exit 0;;
	*)
		prefix=$1;;
	esac
	shift
done

ps -aux > "${prefix}_ps.txt"
lsmod > "${prefix}_lsmod.txt"
netstat -nap > "${prefix}_netstat.txt"

