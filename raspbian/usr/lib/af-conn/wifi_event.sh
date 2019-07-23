#!/bin/sh

count=0
while [ "x`/sbin/ifconfig wlan0 | grep 'inet addr'`" = "x" ] ; do
	/bin/sleep 1
	count=`/usr/bin/expr $count + 1`
	if [ "$count" -gt "10" ] ; then
		break;
	fi
done
