#!/usr/bin/gnuplot

set title "TCP Port Distribution"
set xlabel "TCP Port Number"
set ylabel "Counter value"
set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output "images/tcp_port_dist.png"

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set key right 
set rmargin 5

# Plot 
plot "output/tcp_raw.txt" u 1:xticlabels(1) lc rgb "#FF0000" title "TCP Port Dist. from pcap"