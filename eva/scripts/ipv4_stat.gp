#!/usr/bin/gnuplot

set title "IPv4 Distribution"
set xlabel "IPv4 Number"
set ylabel "Counter value"
set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output "images/ipv4_dist.png"

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set xtics rotate by 45 right
set key right 
set rmargin 5

# Plot 
plot "output/sorted_ip_raw.txt" u 2:xticlabels(1) lc rgb "#FF0000" title "IPv4 Dist. from pcap"