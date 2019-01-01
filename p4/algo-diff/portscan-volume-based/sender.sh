#!/bin/bash

python ../../utils/pktgen/sender.py -v 4 --ip 10.0.2.2 --loop 100 --msg "Benign Traffic" --dport 6666