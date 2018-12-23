#!/bin/bash

function temporal
{
    # set threshold
    simple_switch_CLI < runtime/s1_threshold_temporal.txt
}

function spatial
{
    # set threshold
    simple_switch_CLI < runtime/s1_threshold_spatial.txt
}

if [ $# -eq 0 ]; then
    echo "Usage: $(basename $0) {temporal|spatial}"
    exit
fi

$1

sudo python p4_controller.py \
    --p4info basic_tutorial_switch.p4info \
    --bmv2-json basic_tutorial_switch.json 
