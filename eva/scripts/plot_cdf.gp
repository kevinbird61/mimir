#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename

set title "Cumulative Distribution Function"
set xlabel "Value"
set ylabel "Cumulative Probability"
set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output ARG2

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set xtics rotate by 45 right
set key right 
set rmargin 5

# set yrange 
set yrange [0:1]

# Plot 
# set style line 1 lt 2 lw 10 pt 3 ps 0.5
plot ARG1 u 2:xticlabels(1) lc rgb "#FF0000" lw 5 title "CDF" with linespoints 
