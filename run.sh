#!/bin/bash

cd /home/lobby/uberserver

#kill $(cat uberserver.pid)

/usr/bin/python3 server.py -g args.txt >> server.log 2>&1 & disown
echo $! > uberserver.pid
