
# File: init_firewall.sh
#
# This file is interpreted as shell script.
# Bento's custom iptables rules. The file is invoked via /etc/config/firewall
# which is executed with each firewall (re-)start. It is also invoked by the
# connection manager when it starts
#
# Internal uci firewall chains are flushed and recreated on reload, so
# put custom rules into the root chains e.g. INPUT or FORWARD or into the
# special user chains, e.g. input_wan_rule or postrouting_lan_rule.
#
# ref: original openwrt file: /etc/firewall.user


##############################################################
# Variables
# Note: the rule order is important.  Hence the list of the interface
#       order is important and in the order of its priority.

[ -e /usr/lib/af-conn/get_netif_names ] && source /usr/lib/af-conn/get_netif_names

WHITELIST_INTERFACES="$ETH_INTERFACE_0 $WIFISTA_INTERFACE_0 $WAN_INTERFACE_0"

IPTABLES="/usr/sbin/iptables"

#
# Afero rule chains: for allowed service, whitelist

AFERO_ALLOW_INCOMING_SERVICES=AFERO_ALLOW_SERVICE_INPUT
AFERO_ALLOW_OUTGOING_SERVICES=AFERO_ALLOW_SERVICE_OUTPUT

AFERO_WHITELIST_INPUT_CHAIN=AFERO_ALLOW_WHITELIST_INPUT
AFERO_WHITELIST_OUTPUT_CHAIN=AFERO_ALLOW_WHITELIST_OUTPUT

# Master wifi interface
# By default - the bento is standalon3 and it is a client to the
# customer AP. Bento can became an extender
#
MASTER_WIFI_IFACE="wlan0-1"
is_bento_ap=0

is_bento_a_wifi_ap()
{
    local result

    result=`cat /proc/net/dev | grep -i $MASTER_WIFI_IFACE `
    if [ -n "$result" ]; then
        echo "create_afero_whitelist:: this bento is: master"
        logger "create_afero_whitelist:: this bento is: master"
        is_bento_ap=1
    else
        echo "create_afero_whitelist:: this bento is: station"
        logger "create_afero_whitelist:: this bento is: station"
        is_bento_ap=0
    fi
}

# Create a rule for allowing incoming traffic for supported whitelist IP/addr
# needs two arguments
#  wl_addr=$1
#
create_input_whitelist_rules()
{
    local wl_addr=$1

    echo "$IPTABLES --wait -A $AFERO_WHITELIST_INPUT_CHAIN -s $wl_addr -m state --state ESTABLISHED,RELATED -j ACCEPT"
    $IPTABLES --wait -A $AFERO_WHITELIST_INPUT_CHAIN  -s $wl_addr  \
         -m state --state ESTABLISHED,RELATED -j ACCEPT \
         -m comment --comment "$wl_addr"
}


# Create a rule for allowing outgoing traffic for supported whitelist IP/addr
# needs two arguments
#  wl_addr=$1
#
create_output_whitelist_rules()
{
    local wl_addr=$1

    echo "$IPTABLES --wait -A $AFERO_WHITELIST_OUTPUT_CHAIN -d $wl_addr -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT"
    $IPTABLES --wait -A $AFERO_WHITELIST_OUTPUT_CHAIN  -d $wl_addr \
         -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT \
         -m comment --comment "$wl_addr"
}

#############################################################################
# Flush the INPUT chain, and the OUTPUT chain, afero-based chains
#
echo "Flushing INPUT, OUTPUT, FORWARD chains"
$IPTABLES -F INPUT
$IPTABLES -F OUTPUT 
$IPTABLES -F FORWARD

$IPTABLES -F $AFERO_ALLOW_INCOMING_SERVICES
$IPTABLES -F $AFERO_ALLOW_OUTGOING_SERVICES

#
$IPTABLES -F $AFERO_WHITELIST_INPUT_CHAIN
$IPTABLES -F $AFERO_WHITELIST_OUTPUT_CHAIN


# FORWARDING chain names
#  - create chain names for the FORWARD
AFERO_FORWARD_SERVICE=AFERO_FORWARD_ACCEPT_SERVICE
AFERO_FORWARD_WHITELIST=AFERO_FORWARD_WHITELIST

$IPTABLES -F $AFERO_FORWARD_SERVICE
$IPTABLES -F $AFERO_FORWARD_WHITELIST

$IPTABLES -N $AFERO_FORWARD_SERVICE
$IPTABLES -A FORWARD -j $AFERO_FORWARD_SERVICE

$IPTABLES -N $AFERO_FORWARD_WHITELIST
$IPTABLES -A FORWARD -j $AFERO_FORWARD_WHITELIST
$IPTABLES -A FORWARD -j reject


# INPUT - incoming service allowed
$IPTABLES -N $AFERO_ALLOW_INCOMING_SERVICES
$IPTABLES -t filter -A INPUT  -m comment --comment "Incoming rules supported service needed by Bento" \
        -j $AFERO_ALLOW_INCOMING_SERVICES

# OUTPUT - outgoing service allowed
$IPTABLES -N $AFERO_ALLOW_OUTGOING_SERVICES
$IPTABLES -t filter -A OUTPUT -m comment --comment "Outgoing rules supported service needed by Bento" \
        -j $AFERO_ALLOW_OUTGOING_SERVICES

#
# whitelist -- create the whitelist chain names
#
$IPTABLES -N $AFERO_WHITELIST_INPUT_CHAIN
$IPTABLES -t filter -A INPUT  -m comment --comment "Afero whitelist allowed servers incoming rules" \
            -j $AFERO_WHITELIST_INPUT_CHAIN

$IPTABLES -N $AFERO_WHITELIST_OUTPUT_CHAIN
$IPTABLES -t filter -A OUTPUT  -m comment --comment "Afero whitelist allowed servers outgoing rules" \
        -j $AFERO_WHITELIST_OUTPUT_CHAIN


#############################################################################
# take care the traffic on the loopback interface
#
$IPTABLES -A INPUT -i lo -j ACCEPT -m comment --comment "loopback itf"
$IPTABLES -A OUTPUT -o lo -j ACCEPT -m comment --comment "loopback itf"


#############################################################################
##
## ALLOW DNS connection on wwlan and wwan0 
##       ICMP (request & reply)
##       NTP 
##       DHCP 
##

##
# DNS service 
echo "Specifiy the allowed services"
echo "  -- DNS -- "
for ifname in $WHITELIST_INTERFACES;
do
    # OUTGOING rules
    $IPTABLES -A $AFERO_ALLOW_OUTGOING_SERVICES -p udp -o $ifname --dport 53 -j ACCEPT \
        -m comment --comment "DNS"

    # INCOMING rules
    $IPTABLES -A $AFERO_ALLOW_INCOMING_SERVICES -p udp -i $ifname --sport 53 -j ACCEPT \
        -m comment --comment "DNS"

done
#
# FORWARDING rules
#
# forwarding from extender to master (from bridge lan)
$IPTABLES -A $AFERO_FORWARD_SERVICE -i $BRIDGE_INTERFACE_0 -p udp --dport 53 -j ACCEPT \
    -m comment --comment "DNS request"

# accepting reply from master to extender (via the bridged interface)
$IPTABLES -A $AFERO_FORWARD_SERVICE -o $BRIDGE_INTERFACE_0 -p udp --sport 53 -j ACCEPT \
    -m comment --comment "DNS reply"


# ALLOW outgoing PING (ICMP)
# for each ifname (wlan0,wwan0, eth0)
#
echo "  -- PING -- "
for ifname in $WHITELIST_INTERFACES;
do
    $IPTABLES -A $AFERO_ALLOW_OUTGOING_SERVICES -o $ifname -p icmp --icmp-type echo-request \
        -j ACCEPT -m comment --comment "icmp request rule"
    $IPTABLES -A $AFERO_ALLOW_INCOMING_SERVICES -i $ifname -p icmp --icmp-type echo-reply \
        -j ACCEPT -m comment --comment "icmp reply rule"
done



#
# FORWARDING rules
#
# forwarding from extender to master (from bridged interface)
$IPTABLES -A $AFERO_FORWARD_SERVICE -i $BRIDGE_INTERFACE_0 -p icmp --icmp-type echo-request -j ACCEPT \
        -m comment --comment "icmp request rule"

# accepting reply from master to extender (via the bridged interface)
$IPTABLES -A $AFERO_FORWARD_SERVICE -o $BRIDGE_INTERFACE_0 -p icmp --icmp-type echo-repl -j ACCEPT \
        -m comment --comment "icmp reply rule"



# ALLOW using NTP (as a client)
#
# for each ifname (wlan0,wwan0, eth0)
#
echo "  -- NTP -- "
for ifname in $WHITELIST_INTERFACES;
do
    $IPTABLES -A $AFERO_ALLOW_OUTGOING_SERVICES -o $ifname -p udp --dport 123 \
        -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "NTP rule"

    $IPTABLES -A $AFERO_ALLOW_INCOMING_SERVICES -i $ifname -p udp --sport 123 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "NTP rule"

done
#
# FORWARDING rules
#
# forwarding from extender to master (from bridged interface)
$IPTABLES -A $AFERO_FORWARD_SERVICE -i $BRIDGE_INTERFACE_0 -p udp --dport 123 -j ACCEPT \
        -m comment --comment "NTP"

# accepting reply from master to extender (via the bridged interface)
$IPTABLES -A $AFERO_FORWARD_SERVICE -o $BRIDGE_INTERFACE_0 -p  udp --sport 123 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "NTP"


# ALLOW using DHCP (renewal)
#
echo "  -- DHCP -- "
# for each ifname (wlan0,wwan0, eth0)
#
for ifname in $WHITELIST_INTERFACES;
do 
    $IPTABLES -A $AFERO_ALLOW_INCOMING_SERVICES -i $ifname -p udp --sport 67:68 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "DHCP rule"

    $IPTABLES  -A $AFERO_ALLOW_OUTGOING_SERVICES -o $ifname -p udp --dport 67:68 \
        -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "DHCP rule"
done

###### DHCP on briged interface (br-apnet)
##
## this rule is used for the bento extender, to request a dynamic (dhcp)
## IP address from the bento master.
## iptables -I AFERO_ALLOW_SERVICE_INPUT 1 -i br-apnet -p udp --dport 67:68  \
##     -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
##
## On the Master Benter, the incoming traffic is from bridged interface
##
$IPTABLES -A $AFERO_ALLOW_INCOMING_SERVICES -i $BRIDGE_INTERFACE_0 -p udp --dport 67:68 \
        -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "DHCP:Bento ext -> Bento AP"

## iptables -I AFERO_ALLOW_SERVICE_OUTPUT 1 -o br-apnet -p udp --sport 67:68 -j ACCEPT
$IPTABLES -A $AFERO_ALLOW_OUTGOING_SERVICES -o $BRIDGE_INTERFACE_0 -p udp --sport 67:68 \
        -j ACCEPT -m comment --comment "DHCP:Bento AP -> Bento ext"


#
# FORWARD rules
#
$IPTABLES -A $AFERO_FORWARD_SERVICE -i $BRIDGE_INTERFACE_0 -p udp --sport 67:68 -j ACCEPT \
        -m comment --comment "DHCP rule"

$IPTABLES  -A $AFERO_FORWARD_SERVICE -o $BRIDGE_INTERFACE_0 -p udp --dport 67:68 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "DHCP rule"



# ALLOW SSH for NOW -- TODO: remove before ship
#
# incoming SSH connection (on wifi )
echo "Specifiy the TEMPOARILY/DEV allowed services -- REMOVE BEFORE SHIP"
echo "  -- SSH -- "
$IPTABLES -A INPUT  -i wlan0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"
$IPTABLES -A OUTPUT -o wlan0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"

####### eth0
$IPTABLES -A INPUT  -i eth0 -p tcp --dport 22  -j ACCEPT \
            -m comment --comment "Allow SSH - REMOVE before ship"
$IPTABLES -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT \
            -m comment --comment "Allow SSH - REMOVE before ship"



# outgoing SSH connection (on wifi )
$IPTABLES -A OUTPUT -o wlan0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"
$IPTABLES -A INPUT -i wlan0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"

###### eth0
$IPTABLES -A OUTPUT -o eth0 -p tcp --dport 22 -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"
$IPTABLES -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT \
    -m comment --comment "Allow SSH - REMOVE before ship"


# creates the iptables rules supporting the afero whitelist

WHITELIST_FILE="/etc/af-conn/whitelist"
FWCFG="/usr/lib/af-conn/fwcfg.sh"

#
# Check to make sure the whitelist file exists
#
if [ -f $WHITELIST_FILE ]; then

    is_bento_a_wifi_ap

    # read the whitelist from the file
    # - remove service name with wildcard as iptables cannot resolve dns name
    #   with wildcard in it.
    #
    result=`grep -vE '^(\s*$|#)|\*' $WHITELIST_FILE`

    echo "create_afero_whitelist:: permit service: $result"
    logger "create_afero_whitelist:: permit service: $result"

    #
    # there are entries from the whitelist file
    #
    if [ -n "$result" ]; then
        #
        # Flush the iptable chains for the whitelist
        #
        logger "Whitelist services: Flash WHITELIST INPUT and OUTPUT"
        $IPTABLES -F $AFERO_WHITELIST_INPUT_CHAIN
        $IPTABLES -F $AFERO_WHITELIST_OUTPUT_CHAIN

        #
        # for each ADDR/IP specified in the whitelist
        #
        for addr in $result;
        do
            echo "whitelisting service:: Updating WHITELIST INPUT and OUTPUT for service: $addr"
            logger "Whitelist services:: Updating WHITELIST INPUT and OUTPUT for service: $addr"

            create_input_whitelist_rules $addr

            create_output_whitelist_rules $addr

            # the BENTO is an AP (i.e - master to an extender)
            # Let's define the FORWARDING accept rules
            if [ $is_bento_ap -eq 1 ]; then

                # adding a rule for this service addr
                echo "Whitelist services:: add forwarding rule: $addr"
                logger "Whitelist services:: add forwarding rule: $addr"

                $FWCFG add_forwarding $addr

            fi
        done
    fi

else
    echo "Whitelist services failed: No such file: $WHITELIST_FILE"
    logger "Whitelist services failed: No such file: $WHITELIST_FILE"
    exit 1
fi
