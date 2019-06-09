#!/bin/bash

function controller()
{
    sudo python p4controller.py --p4info basic_tutorial_switch.p4info --bmv2-json basic_tutorial_switch.json
}

function switch()
{
    sudo simple_switch_grpc -i 1@br_atk -i 2@br_vic --device-id 0 -- basic_tutorial_switch.json
}

# execute specified function
$1