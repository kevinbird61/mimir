EXECS:=read_pcap.out hash_pcap.out port_diff.out heavy_hitter.out srr.out bitmap_control.out 
UTILS:=sort.out entro.out sdiff.out pktlen.out birth.out tcp_flags.out ewma_pktlen.out flowlet.out port_dist.out
TESTS:=test_hash.out
BITMAP:=bcm1.out bcm2.out bcm3.out bcm4.out bcm4_nomap.out bcm5.out bcm7.out bcm_all_without_eb.out bcm_only_update_first.out bcm_without_eb_mod4_diffcnt.out
CXXFLAGS:= -std=c++11

all: $(EXECS) $(UTILS) $(TESTS) $(BITMAP)

# bitmap control
bcm1.out: hash.o xxhash.o bitmap_control_mod1.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm2.out: hash.o xxhash.o bitmap_control_mod2.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm3.out: hash.o xxhash.o bitmap_control_mod3.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm4.out: hamm.o hash.o xxhash.o bitmap_control_mod4.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm4_nomap.out: hamm.o hash.o xxhash.o bitmap_control_mod4_nonmap.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm5.out: hash.o xxhash.o bitmap_control_mod5.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm7.out: hash.o xxhash.o bitmap_control_mod7.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm_all_without_eb.out: hash.o xxhash.o bitmap_control_without_e_bitmap.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm_only_update_first.out: hash.o xxhash.o bitmap_control_only_firstpkt_flowlet.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bcm_without_eb_mod4_diffcnt.out:  hash.o xxhash.o bitmap_control_without_eb_mod4_diffcnt.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)

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
srr.out: hash.o xxhash.o sent_recv_ratio.cc
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)
bitmap_control.out: hash.o xxhash.o bitmap_control.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib -Ithird_party $(CXXFLAGS)

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
flowlet.out: utils/flowlet.cc 
	g++ $^ -o $@ -lm -lpcap -Ilib $(CXXFLAGS)
port_dist.out: utils/port_dist.cc
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