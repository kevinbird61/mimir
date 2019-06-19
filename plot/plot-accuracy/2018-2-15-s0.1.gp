#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename

set terminal png font " Times_New_Roman,12 "
set output ARG2

set yrange [0: 100]
set ytics
set y2range
set y2tics 

set title "Plot using boxed labels"
set xlabel "Type of detection threshold"
set ylabel "True Positive Rate (%)"
set y2label "False Positive Rate (%)"

plot ARG1 using 2:xticlabels(1) title "TP rate(tsize=128)" with linespoint lw 3 lc rgb "#FF0000", \
     ''   using 3:xticlabels(1) title "FP rate(tsize=128)" with linespoint lw 3 lc rgb "#FF00FF" axes x1y2, \
     ''   using 6:xticlabels(1) title "TP rate(tsize=1024)" with linespoint lw 3 lc rgb "#0000FF", \
     ''   using 7:xticlabels(1) title "FP rate(tsize=1024)" with linespoint lw 3 lc rgb "#00FFFF" axes x1y2, \