#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename
# ARG3: title of xlabel

set terminal png font " Times_New_Roman,12 " size 800, 600
set output ARG2

#set yrange [0: 100]
set ytics

# If error enable, then uncommment
# set y2range [0:ARG3]
#set y2tics 

set title "Collision rate Control"
set xlabel ARG3
set ylabel "Collision Rate (%)"
# set y2label "Number of False Alarms (NFA)"

set xtics rotate by 45 right
set key right 
# set rmargin 5

plot ARG1 using 2:xticlabels(1) title "Control Line" with linespoint lw 3 lc rgb "#FF0000"