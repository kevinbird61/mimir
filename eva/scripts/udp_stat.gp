#!/usr/bin/gnuplot

set title "UDP Port Distribution"
set xlabel "UDP Port Number"
set ylabel "Counter value"
set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output "images/udp_port_dist.png"

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set key right 
set rmargin 5

# Plot 
plot "output/sorted_udp_raw.txt" u 2:xticlabels(1) lc rgb "#FF0000" title "UDP Port Dist. from pcap"