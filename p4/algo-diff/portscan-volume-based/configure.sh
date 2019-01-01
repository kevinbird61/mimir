#!/bin/bash

# (conti. from build.sh) Step 3: configuration  
#   - 9090: s1 (default port value)
#   - 9091: s2 
#   - ... (iterative) 
simple_switch_CLI --thrift-port 9090 < runtime/configuration.txt
simple_switch_CLI --thrift-port 9091 < runtime/configuration.txt
simple_switch_CLI --thrift-port 9092 < runtime/configuration.txt