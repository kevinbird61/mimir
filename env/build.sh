#!/bin/bash

# windows/linux (need to modify when your env change)
# docker executable file 
#DOCKER="/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe"
DOCKER="docker"

# initial environment setting for virtual network
function init()
{
    echo "Initializing our virtual network..."
    # create bridge (to seperate victim network and attacker network)
    echo "Create bridge ..."
    # Specify their subnet information and ip-range.
    # atk will be 172.28.0.0/16
    "$DOCKER" network create --driver bridge "atk" --opt com.docker.network.bridge.name=br_atk --subnet=172.28.0.0/16 --ip-range=172.28.1.0/24 
    # and vic will be 172.30.0.0/16 
    "$DOCKER" network create --driver bridge "vic" --opt com.docker.network.bridge.name=br_vic --subnet=172.30.0.0/16 --ip-range=172.30.1.0/24 
}

function clean()
{
    # clean all 
    "$DOCKER" stop $("$DOCKER" ps -a -q)
    "$DOCKER" rm $("$DOCKER" ps -a -q)
    # remove all bridge
    "$DOCKER" network rm "atk"
    "$DOCKER" network rm "vic"
}

function create()
{    
    # $1: name
    # $2: network
    echo "Create new virtual host: " $1 
    echo "Default network interface: " $2

    # Start our container
    # docker run -t -d --name "user"$2 kevinbird61/vnet
    "$DOCKER" run -t -d --name "$1" --network "$2" kevinbird61/vnet
}

function run()
{
    # $1: name
    # $2: command 
    # -d: running in background
    echo "Running command: $2"
    "$DOCKER" exec -i -d "$1" "$2"
}


if [ $# -eq 0 ]; then
    echo "Usage: $(basename $0) {create}"
    echo "\t$(basename $0)"
    exit
fi

if [ "$1" == "create" ]; then
    # $2 = name of host device
    # $3 = network of device
    $1 $2 $3
    exit
elif [ "$1" == "run" ]; then 
    # $2 = name
    # $3 = cmd 
    $1 $2 $3
    exit
fi

$1
