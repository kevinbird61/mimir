#!/bin/sh

# set threshold
simple_switch_CLI < runtime/s1_threshold.txt

sudo python p4_controller.py \
    --p4info basic_tutorial_switch.p4info \
    --bmv2-json basic_tutorial_switch.json 
