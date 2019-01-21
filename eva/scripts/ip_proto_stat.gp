#!/usr/bin/gnuplot

set title "IP Protocol Distribution"
set xlabel "Protocol"
set ylabel "Counter value"
set terminal png font " Times_New_Roman,12 "
set output "images/ip_proto_stat.png"

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x
set style data histogram
set style fill solid border -1
set boxwidth 0.9

set key right 

# Plot 
plot "output/proto_raw.txt" u 2:xticlabels(1) lc rgb "#FF0000" title "Proto Dist. from pcap"