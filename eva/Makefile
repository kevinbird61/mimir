EXECS:=read_pcap.out hash_pcap.out port_diff.out heavy_hitter.out
UTILS:=sort.out entro.out sdiff.out pktlen.out birth.out tcp_flags.out ewma_pktlen.out
TESTS:=test_hash.out
CXXFLAGS:= -std=c++11

all: $(EXECS) $(UTILS) $(TESTS)

# executable file
read_pcap.out: cmap.o pktstat.o read_pcap.c 
	gcc $^ -o $@ -lpcap -Ithird_party
read_pcap_w.out: cmap.o pktstat.o read_pcap.c 
	# run and write the statistics into txt
	gcc $^ -o $@ -DWRITE -lpcap -Ithird_party
hash_pcap.out: hash.o xxhash.o hash_pcap.c
	gcc $^ -o $@ -lpcap -Ithird_party
port_diff.out: cmap.o hash.o xxhash.o hamm.o port_diff.c 
	gcc $^ -o $@ -lm -lpcap -Ithird_party
heavy_hitter.out: cmap.o hash.o xxhash.o pktstat.o heavy_hitter.c
	gcc $^ -o $@ -lm -lpcap -Ithird_party

# utils
sort.out: utils/sort.cc 
	g++ $^ -o $@ -lm $(CXXFLAGS)
entro.out: utils/entropy.cc
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)
sdiff.out: utils/statistical_diff.cc
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)
pktlen.out: hamm.o utils/pktlen.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)
birth.out: utils/birthday.cc
	g++ $^ -o $@ -lm $(CXXFLAGS)
ewma_pktlen.out: utils/ewma_pktlen.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)
tcp_flags.out: utils/tcp_flags.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)

# test
test: utils/mini_pcap.cc 
	g++ $^ -o test.out -lm -lpcap -Ilib $(CXXFLAGS)
test_hash.out: utils/test_hash.cc xxhash.o hash.o
	g++ $^ -o $@ -Ithird_party -Ilib $(CXXFLAGS)

# plot 
plot_read_pcap:
	gnuplot scripts/ip_proto_stat.gp 
	gnuplot scripts/tcp_stat.gp 
	gnuplot scripts/udp_stat.gp 
	gnuplot scripts/ipv4_stat.gp

# Object files
pktstat.o: lib/packet_stat.c 
	gcc -o pktstat.o -c lib/packet_stat.c -Ithird_party
cmap.o: third_party/cmap/map.c 
	gcc -o cmap.o -c third_party/cmap/map.c 
xxhash.o: third_party/hash/xxhash.c 
	gcc -o xxhash.o -c third_party/hash/xxhash.c 
hash.o: lib/hash.c 
	gcc -o hash.o -c lib/hash.c
hamm.o: lib/hamming.c
	gcc -o $@ -c lib/hamming.c


clean:
	rm *.o *.out 