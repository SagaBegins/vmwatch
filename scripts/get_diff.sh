#!/bin/bash

comms=(ps lsmod netstat)

sep="##########################################"

for comm in "${comms[@]}"
do
	echo "$sep START ${comm^^} DIFF $sep"
	diff -u "bf_${comm}.txt" "af_${comm}.txt"
	echo "$sep# END ${comm^^} DIFF $sep#"
	echo ''
done
