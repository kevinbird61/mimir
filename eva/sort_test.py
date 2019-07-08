dict={ 10.0: {"ev10", "erwer"}, 11.0: {"ev11"}, 40.0: {"ev40", "1234"}, 23: {"ev23", "1231"}}

print "sort 1:"
print sorted(dict.items(), key=lambda d: d[0])

print "sort 2:"
for key in sorted(dict.keys()) :
    print key , " :: " , dict[key]