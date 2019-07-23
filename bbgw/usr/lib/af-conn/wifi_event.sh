#!/bin/sh
#
### BEGIN USAGE INFO
#
# Required for:         networking
# Used by:              wifistad daemon
# Required by platform: Raspberry Pi3
# Short-Description:    Stop current udhcpc for wifi interface, and restart it
#                       This allow switching AP to work properly.
#
### END USAGE INFO

set -e

ECHO="/bin/echo"
UDHCPC="/sbin/udhcpc"
NOHUP="/usr/bin/nohup"
USLEEP=/bin/usleep

. /usr/lib/af-conn/get_netif_names


######################
#
# terminate the udhcpc process for the wifi interface
# and restart again.
#
restart_udhcpc_for_wifi()
{
	UDHCPC_PROCESSES=`ps | /bin/grep udhcpc | /bin/grep $WIFISTA_INTERFACE_0 | /usr/bin/awk '{print $1}' `

	# terminate the udhcpc process for WIFI
	for ii in $UDHCPC_PROCESSES ; do
		/bin/kill -9  $ii
	done

	# start udhcpc
	${UDHCPC} -R -b -p /var/run/udhcpc.$WLAN_INTERFACE_NAME.pid -i $WIFISTA_INTERFACE_0

	return 0;
}


#####################
#
# restart the wpa_supplicant process
#
restart_wpa_supplicant()
{
	reboot

	return 0
}

#####################
# usage
#
usage()
{
	${ECHO} "usage -- wificfg connected|disconnected|start_wpa_supplicant "
	${ECHO} "      "
}


case `${ECHO} $1 | tr 'A-Z' 'a-z' ` in

    conn|connected)
        restart_udhcpc_for_wifi;  res=$?
        ;;

    disc|disconnected)
		${ECHO} "command $1 is not supported yet"
        ;;

    start_wpa_supplicant)
        restart_wpa_supplicant; res=$?
        ;;

    *) usage ; exit 1 ;;

esac
exit $res

