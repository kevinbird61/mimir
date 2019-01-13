all: read_pcap 

read_pcap: cmap.o pktstat.o 
	gcc -o read_pcap.out cmap.o pktstat.o read_pcap.c -lpcap
	gcc -o read_pcap_w.out -DWRITE cmap.o pktstat.o read_pcap.c -lpcap # run and write the statistics into txt

pktstat.o: packet_stat.c 
	gcc -o pktstat.o -c packet_stat.c 

cmap.o: third_party/cmap/map.c 
	gcc -o cmap.o -c third_party/cmap/map.c 

clean:
	rm *.o *.out 