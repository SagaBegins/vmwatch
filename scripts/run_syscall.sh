#!/bin/bash

gcc /root/sim_syscall_175.c -o syscall

#echo $1
./syscall "$1" 
