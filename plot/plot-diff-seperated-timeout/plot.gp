#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename
# 

set terminal png font " Times_New_Roman,12 " size 800, 600
set output ARG2

set yrange [0: 100]
set ytics

# If error enable, then uncommment
# set y2range
set y2tics 

set title "Sampled flow Percentage and Accuracy"
set xlabel "N% sampled flow"
set ylabel "True Positive Rate (%)"
set y2label "Number of False Alarms (NFA)"

set xtics rotate by 45 right
set key right 
# set rmargin 5

plot ARG1 using 2:xticlabels(1) title "TP" with linespoints lw 3 lc rgb "#FF0000", \
    '' using 4:xticlabels(1) title "NFA" with linespoints lw 3 lc rgb "#77FF00" axes x1y2