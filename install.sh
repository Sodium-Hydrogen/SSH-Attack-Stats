#!/bin/sh

read -rp "To install you will need sudo level permissions. Continue? [y/n] " key

if [ $key = "y" ] || [ $key = "Y" ]; then
	cp ./42-log-stats /etc/update-motd.d/
	chmod 755 /etc/update-motd.d/42-log-stats
	g++ ./stats.cpp -o /usr/local/bin/log-stats.bin
	cp ./conversion.txt /usr/local/bin/conversion.txt
	echo "done"
fi
