LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o
	cc -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.c
	cc -c -o pcap-test.o pcap-test.c

clean:
	rm -f *.o pcap-test