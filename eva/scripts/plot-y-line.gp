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
#set auto x 
#set logscale
#set xrange [0:1000]

#unset xtics

#set style data histogram
#set style fill solid border -1

set xtics rotate by 45 right
set key right 
set rmargin 5
# set xtic scale 0
#set xtics autofreq 10


#set for [i=0:10] xtics (100*i)

# Plot 
# set style line 1 lt 2 lw 10 pt 3 ps 0.5
set logscale x
set arrow from 1,10 to 1e7,10 nohead lw 5 lc rgb "#0000FF"
# plot ARG1 u 2:xticlabels(1) lc rgb "#FF0000" lw 5 title ARG1 with linespoints 
plot ARG1 u 1:2 lc rgb "#FF0000" lw 2 title "" with linespoints 



print "Done."
print "========================================================"