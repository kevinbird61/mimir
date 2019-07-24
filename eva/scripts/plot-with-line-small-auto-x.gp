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


set title ARG5
set xlabel ARG3
set ylabel ARG4
set terminal png font " Times_New_Roman,12 "
set output ARG2

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set xtics rotate by 45 right
set key right 
set rmargin 5

#set arrow from ARG6,0 to ARG6,ARG7 nohead lw 5 lc rgb "#00FF00"

# Plot 
# set style line 1 lt 2 lw 10 pt 3 ps 0.5
# plot ARG1 u 2:xticlabels(1) lc rgb "#FF0000" lw 5 title ARG1 with linespoints 
plot ARG1 u 2:xticlabels(1) lc rgb "#FF0000" lw 5 with linespoints notitle

print "Done."
print "========================================================"