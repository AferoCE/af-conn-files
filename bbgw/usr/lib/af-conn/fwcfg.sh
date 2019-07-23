#!/bin/sh

# fwcfg -- null firewall configuration script for hubs without firewalls
#
# Copyright 2017 (c) Afero, Inc. All rights reserved.

#if [ -f /etc/config/create_afero_whitelist.sh ]; then
#. /etc/config/create_afero_whitelist.sh
#fi

ECHO="/bin/echo"
IPTABLES="/usr/sbin/iptables"
LOGGER="/usr/bin/logger"


. /usr/lib/af-conn/get_netif_names


#
# The forwarding chain names (must be under 29 chars)
#
AFERO_FORWARD_SERVICE="AFERO_FORWARD_ACCEPT_SERVICE"
AFERO_FORWARD_WHITELIST="AFERO_FORWARD_WHITELIST"


# usage
#
usage()
{
    ${ECHO} "usage -- fwcfg.sh add|del|add_forwarding|del_forwarding <ip_addr> <comment> [check_fw]"
    ${ECHO} "      -- fwcfg.sh restart"
    ${ECHO} "      "
    ${ECHO} " <ip_addr> : IP address"
    ${ECHO} " <comment> : comment or dns name"
    ${ECHO} " <check_fw>: 0 or 1, 1 indicates to check existing rule for <ip_addr> when add"
}


#
# check to see if there is a rule with this address already in
# this specified firewall chain.
#
is_this_addr_in_whitelist_rules()
{
    local addr=$1
    local fw_chain_name=$2
    local result

    result=`$IPTABLES -nvxL $fw_chain_name | grep -w "$addr"`
    if [ -z "$result" ];
    then
        return 0
    fi
    return 1
}


# Create a rule for allowing incoming traffic for supported whitelist IP/addr
# needs two arguments
#  wl_addr=$1
#  extra_comment=$2
create_input_whitelist_rules()
{
    local wl_addr=$1
    local extra_comment=$2

    echo "$IPTABLES --wait -A AFERO_ALLOW_WHITELIST_INPUT -s $wl_addr -m state --state ESTABLISHED,RELATED -j ACCEPT"

    $IPTABLES --wait -A AFERO_ALLOW_WHITELIST_INPUT -s $wl_addr \
              -m state --state ESTABLISHED,RELATED -j ACCEPT \
              -m comment --comment "$wl_addr - $extra_comment"
}


# Create a rule for allowing outgoing traffic for supported whitelist IP/addr
# needs two arguments
#  wl_addr=$1
#  extra_comment=$2
create_output_whitelist_rules()
{
    local wl_addr=$1
    local extra_comment=$2

    echo "$IPTABLES --wait -A AFERO_ALLOW_WHITELIST_OUTPUT -d $wl_addr -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT"
    $IPTABLES --wait -A AFERO_ALLOW_WHITELIST_OUTPUT -d $wl_addr \
              -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT \
              -m comment --comment "$wl_addr - $extra_comment"
}


# Delete a rule for allowing incoming traffic for supported whitelist IP/addr
# needs two arguments
#  wl_addr=$2
#  extra_comment=$2
delete_input_whitelist_rules()
{
    local wl_addr=$1
    local extra_comment=$2

    echo "$IPTABLES --wait -D AFERO_ALLOW_WHITELIST_INPUT -s $wl_addr -m state --state ESTABLISHED,RELATED -j ACCEPT"
    $IPTABLES --wait -D AFERO_ALLOW_WHITELIST_INPUT -s $wl_addr \
              -m state --state ESTABLISHED,RELATED -j ACCEPT \
              -m comment --comment "$wl_addr - $extra_comment"
}


fw_add_rule()
{
    # Add a rule to AFERO_ALLOW_WHITELIST_INPUT
    local addr=$1
    local extra_comment=$2
    local check=${3:-0}
    $LOGGER "fwcfg_null_add_rule:ipaddr=$addr,extra_comment=$extra_comment,check=$check:rule change ignored"
    return 0
}


fw_del_rule()
{
    local addr=$1
    local extra_comment=$2

    $LOGGER "fwcfg_null_del_rule:ipaddr=$addr,extra_comment=$extra_comment:rule change ignored"
    return 0
}


#
# This applies to the master and extender configuration only.
#
# In the master and extender configuration, we create a
# bridged interface on the master to bridge the extender. In order to pass the
# traffic, we need to punch holes for the traffic to pass through.
#
# This function allow the 'user' to add a forwarding rule to a
# the bridge lan zone (with interface: br-apnet)
#
fw_add_forwarding_rule()
{
    local addr=$1
    local extra_comment=$2
    local check=${3:-0}

    $LOGGER "fwcfg_add_forwarding_rule:ipaddr=$addr,whitelist=$AFERO_FORWARD_WHITELIST,extra_comment=$extra_comment,check=$check:rule change ignored"
    return 0
}


#
# This function allow the 'user' to delete a defined fw forwarding rule
# for the 'bridge' lan network (interface br-lan)
#
fw_del_forwarding_rule()
{
    local addr=$1
    local extra_comment=$2

    $LOGGER "fwcfg_del_forwarding_rule:ipaddr=$addr,whitelist=$AFERO_FORWARD_WHITELIST,extra_comment=$extra_comment:rule change ignored"
    return 0
}


fw_restart()
{
    $LOGGER "fwcfg_restart_firewall::restart ignored"
    return 0
}


#  usage
#  fwcfg.sh add|del|add_forwarding|del_forwarding <ipaddr> <check_fw> [<extra_comment>]
#  fwcfg.sh restart
#
res=0

ipaddr=$2
extra_comment=$3
check_fw=${4:-0}

#echo "operation=$1  ipaddr=$2  check_fw=$check_fw extra_comment=$3"
#$LOGGER "operation=$1  ipaddr=$2  check_fw=$check_fw extra_comment=$3"


# if ipaddr is NULL, done
if [ -z "$ipaddr" ];
then
    if [ "$1" != 'restart' ]; then
        usage
        exit 1
    fi
fi

case `${ECHO} $1 | tr 'A-Z' 'a-z' '_'` in

    add) fw_add_rule $ipaddr $extra_comment $check_fw; res=$? ;;

    del) fw_del_rule $ipaddr $extra_comment; res=$? ;;

    add_forwarding) fw_add_forwarding_rule $ipaddr $extra_comment $check_fw; res=$?;;

    del_forwarding) fw_del_forwarding_rule $ipaddr $extra_comment; res=$?;;

    restart) fw_restart; res=$?;;

    *) usage ; exit 1 ;;

esac
exit $res

