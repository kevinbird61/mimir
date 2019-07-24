#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename
# ARG3: X-label
# ARG4: Y-label 
# ARG5: Title
# ARG6: Vertical line X 
# ARG7: Vertical line Y (second point)

set title "Estimation Error (Sampled rate)"
set xlabel "Detection timeout (second)"
set ylabel "Percentage (%)"
set terminal png font " Times_New_Roman,12 " 
set output ARG2

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
# set style data histogram
# set style fill solid border -1

set xtics rotate by 45 right
set key right bottom
# set rmargin 5
#set yrange [0:100]
#set y2range [0:230]
#set y2label "Number of false alarm (Amount)"
# set arrow from ARG6,0 to ARG6,ARG7 nohead lw 5 lc rgb "#00FF00"
# set style data lines

# Plot 
# set style line 1 lt 2 lw 10 pt 3 ps 0.5
plot ARG1 u 2:xticlabels(1) lw 5 title "Sampled rate (Simulation)" with linespoints, \
    '' u 3:xticlabels(1) lw 3 title "Sampled rate (E[W])" with linespoints, \

print "Done."
print "========================================================"