#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename

set terminal png font " Times_New_Roman,12 "
set output ARG2

set yrange [0: 100]
set ytics

# If error enable, then uncommment
#set y2range
set y2tics 

set title "Sampled ratio with detection timeout"
set xlabel "Detection timeout (sec.)"
set ylabel "Sampled ratio (%)"
set y2label "Error (%)"

set xtics rotate by 45 right
set key right 
# set rmargin 5

plot ARG1 using 2:xticlabels(1) title "Real" with linespoint lw 3 lc rgb "#FF0000", \
     ''   using 3:xticlabels(1) title "E[W]" with linespoint lw 3 lc rgb "#00FFFF", \
     ''   using 4:xticlabels(1) title "Error by E[W]" with linespoint lw 3 lc rgb "#0000FF" axes x1y2, \
     

#''   using 5:xticlabels(1) title "E[W]" with linespoint lw 3 lc rgb "#00FFFF", \
#''   using 6:xticlabels(1) title "Error by E[W]" with linespoint lw 3 lc rgb "#000000" axes x1y2, \