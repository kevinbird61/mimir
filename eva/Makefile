all: read_pcap hash_pcap

read_pcap: cmap.o pktstat.o 
	gcc -o read_pcap.out cmap.o pktstat.o read_pcap.c -lpcap -Ithird_party
	gcc -o read_pcap_w.out -DWRITE cmap.o pktstat.o read_pcap.c -lpcap -Ithird_party # run and write the statistics into txt

hash_pcap: cmap.o hash.o 
	gcc -o hash_pcap.out cmap.o hash.o hash_pcap.c -lpcap -Ithird_party

pktstat.o: lib/packet_stat.c 
	gcc -o pktstat.o -c lib/packet_stat.c -Ithird_party

cmap.o: third_party/cmap/map.c 
	gcc -o cmap.o -c third_party/cmap/map.c 

hash.o: lib/hash.c 
	gcc -o hash.o -c lib/hash.c 

clean:
	rm *.o *.out 