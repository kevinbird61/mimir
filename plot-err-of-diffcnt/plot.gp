#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename

set terminal png font " Times_New_Roman,12 "
set output ARG2

set yrange [0: 100]
set ytics

# If error enable, then uncommment
set y2range [0:10]
set y2tics 

set title "MAP/Non-MAP comparison"
set xlabel "Detection threshold set"
set ylabel "True Positive Rate (%)"
set y2label "Number of False Alarms (NFA)"

set xtics rotate by 45 right
set key right 
# set rmargin 5

plot ARG1 using 2:xticlabels(1) title "TP of MAP" with linespoint lw 3 lc rgb "#FF0000", \
     ''   using 4:xticlabels(1) title "NFA of MAP" with linespoint lw 3 lc rgb "#0000FF" axes x1y2, \
     ''   using 6:xticlabels(1) title "TP of Non-MAP" with linespoint lw 3 lc rgb "#00FFFF", \
     ''   using 8:xticlabels(1) title "NFA of Non-MAP" with linespoint lw 3 lc rgb "#000000" axes x1y2, \