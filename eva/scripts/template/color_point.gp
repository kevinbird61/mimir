set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output "test.png"

# Input file Format:
#6.37026 2.42441 0
#4.16001 6.55597 2
#3.54946 7.15539 2
#4.35229 3.8448 1
#7.12706 1.2563 3
#1.98478 8.68739 0
#7.67213 2.22039 0
#3.85744 7.3549 1


plot("color_point.txt") with points palette