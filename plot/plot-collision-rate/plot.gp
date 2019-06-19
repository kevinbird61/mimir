#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename
# ARG3: Y2 Upperbound

set terminal png font " Times_New_Roman,12 " size 800, 600
set output ARG2

set yrange [0: 100]
set ytics

# If error enable, then uncommment
set y2range [0:ARG3]
set y2tics 

set title "Collision rate and Accuracy"
set xlabel "Detection threshold set"
set ylabel "True Positive Rate (%)"
set y2label "Number of False Alarms (NFA)"

set xtics rotate by 45 right
set key right 
# set rmargin 5

plot ARG1 using 2:xticlabels(1) title "TP of MAP" with linespoint lw 3 lc rgb "#FF0000", \
     ''   using 4:xticlabels(1) title "NFA of MAP" with linespoint lw 3 lc rgb "#77FF00" axes x1y2, \
     ''   using 6:xticlabels(1) title "TP of Non-MAP(d=1024)" with linespoint lw 3 lc rgb "#00FFFF", \
     ''   using 8:xticlabels(1) title "NFA of Non-MAP(d=1024)" with linespoint lw 3 lc rgb "#0000FF" axes x1y2, \
     ''   using 10:xticlabels(1) title "TP of Non-MAP(d=512)" with linespoint lw 3 lc rgb "#FFFF00", \
     ''   using 12:xticlabels(1) title "NFA of Non-MAP(d=512)" with linespoint lw 3 lc rgb "#9900FF" axes x1y2, \
     ''   using 14:xticlabels(1) title "TP of Non-MAP(d=256)" with linespoint lw 3 lc rgb "#FF00FF", \
     ''   using 16:xticlabels(1) title "NFA of Non-MAP(d=256)" with linespoint lw 3 lc rgb "#FF8800" axes x1y2, \
     ''   using 18:xticlabels(1) title "TP of Non-MAP(d=128)" with linespoint lw 3 lc rgb "#CBACDE", \
     ''   using 20:xticlabels(1) title "NFA of Non-MAP(d=128)" with linespoint lw 3 lc rgb "#660077" axes x1y2