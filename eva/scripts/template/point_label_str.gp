set terminal png font " Times_New_Roman,12 "
set output "test.png"

# Input file format:
# 1 2 test1 
# 3 5 test3 
# 4 9 test4 

set datafile separator " "
set offset 1,1,1,1
plot 'label.txt' using 1:2 notitle, \
     '' using 1:2:3 with labels offset 0, char 1 notitle 