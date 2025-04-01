#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage()
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct
{
	char *dev_;
} Param;

Param param = {
	.dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// MAC 주소를 xx:xx:xx:xx:xx:xx 형식으로 출력하는 함수
void print_mac_address(u_char *mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Ethernet 헤더 정보 출력
void print_ethernet_info(struct libnet_ethernet_hdr *eth_hdr)
{
	printf("Ethernet Header\n");
	printf("   Src MAC: ");
	print_mac_address(eth_hdr->ether_shost);
	printf("\n   Dst MAC: ");
	print_mac_address(eth_hdr->ether_dhost);
	printf("\n");
}

// IP 헤더 정보 출력
void print_ip_info(struct libnet_ipv4_hdr *ip_hdr)
{
	struct in_addr src_ip, dst_ip;
	src_ip.s_addr = ip_hdr->ip_src.s_addr;
	dst_ip.s_addr = ip_hdr->ip_dst.s_addr;
	printf("IP Header\n");
	printf("   Src IP: %s\n", inet_ntoa(src_ip));
	printf("   Dst IP: %s\n", inet_ntoa(dst_ip));
}

// TCP 헤더 정보 출력
void print_tcp_info(struct libnet_tcp_hdr *tcp_hdr)
{
	printf("TCP Header\n");
	printf("   Src Port: %u\n", ntohs(tcp_hdr->th_sport));
	printf("   Dst Port: %u\n", ntohs(tcp_hdr->th_dport));
}

// Payload(최대 20바이트) hexadecimal 값 출력
void print_payload(u_char *payload, int payload_length)
{
	int data_print_length = payload_length < 20 ? payload_length : 20;
	printf("Payload (first %d bytes):\n", data_print_length);
	for (int i = 0; i < data_print_length; i++)
	{
		printf("%02x ", payload[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL)
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		//////////////START MY CODE FROM HERE//////////////
		// Ethernet 헤더 처리
		if (header->caplen < sizeof(struct libnet_ethernet_hdr))
			continue;
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;

		// IPv4 패킷인지 확인 (Ethernet 타입 0x0800)
		if (ntohs(eth_hdr->ether_type) != 0x0800)
			continue;

		// IP 헤더 처리
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
		int ip_header_length = ip_hdr->ip_hl * 4;
		if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_length)
			continue;

		// TCP 프로토콜 여부 확인
		if (ip_hdr->ip_p != IPPROTO_TCP)
			continue;

		// TCP 헤더 처리
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_length);
		int tcp_header_length = tcp_hdr->th_off * 4;
		if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length)
			continue;

		// Payload 처리
		int header_size = sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length;
		int payload_length = header->caplen - header_size;
		const u_char *payload = packet + header_size;

		// 각 정보 출력
		print_ethernet_info(eth_hdr);
		print_ip_info(ip_hdr);
		print_tcp_info(tcp_hdr);
		print_payload((u_char *)payload, payload_length);
	}

	pcap_close(pcap);
}
