set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output "test.png"


# Input file format:
#
# # Year  Red   Green  Blue
# 1990    33    45     18
# 1991    35    42     19
# 1992    34    44     14
# 1993    37    43     25
# 1994    47    15     30
# 1995    41    14     32
# 1996    42    20     35
# 1997    39    21     31
#

plot "test.txt" u 2 t "Red" w histograms, "" u 3 t "Green" w histograms, "" u 4 t "Blue" w histograms, 22 title ""