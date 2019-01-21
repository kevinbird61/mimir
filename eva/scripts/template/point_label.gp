set terminal png font " Times_New_Roman,12 "
set output "test.png"

# Input file format:
# 1 2  
# 3 5  
# 4 9 

set offset 1,1,1,1
plot 'label.txt' using 1:2:(sprintf("(%f, %f)", $1, $2)) with labels point  pt 7 offset char 1,1 notitle