#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename 
# ARG2: output filename
# ARG3: X-label
# ARG4: Y-label 
# ARG5: Title
# ARG6: Vertical line X 
# ARG7: Vertical line Y (second point)

print "========================================================"
print "Input source filename: ", ARG1
print "Output image filename: ", ARG2
print "Text of Xlabel: ", ARG3
print "Text of Ylabel: ", ARG4
print "Title of figure: ", ARG5
print "========================================================"


set title "Impact of threshold (unique dport)"
set xlabel "Threshold value"
set ylabel "Detection rate (%)"
set terminal png font " Times_New_Roman,12 " size 1080,600
set output ARG2

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
# set style data histogram
# set style fill solid border -1

set xtics rotate by 45 right
set key outside
# set rmargin 5
set yrange [0:100]

set y2tics 
set y2range [0:230]
set y2label "Number of false alarm (Amount)"
# set arrow from ARG6,0 to ARG6,ARG7 nohead lw 5 lc rgb "#00FF00"
# set style data lines

# Plot 
# set style line 1 lt 2 lw 10 pt 3 ps 0.5
plot ARG1 u 2:xticlabels(1) lw 2 title "Detection rate" with linespoints, \
    '' u 3:xticlabels(1) lw 2 title "Number of false alarm" with linespoints axis x1y2, \

print "Done."
print "========================================================"