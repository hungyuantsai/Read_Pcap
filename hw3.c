#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include "Color.h"
#include "ethertype.h"
#include <unistd.h>

/* https://www.itread01.com/content/1545589271.html */

#define IFSZ 16
#define FLTRSZ 120
#define MAXHOSTSZ 256

int packets = 0;   /* running count of packets read in */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address      */
        u_short ether_type;                     /* IP? ARP? RARP? etc       */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service                   */
        u_short ip_len;                 /* total length                      */
        u_short ip_id;                  /* identification                    */
        u_short ip_off;                 /* fragment offset field             */
        #define IP_RF 0x8000            /* reserved fragment flag            */
        #define IP_DF 0x4000            /* dont fragment flag                */
        #define IP_MF 0x2000            /* more fragments flag               */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits         */
        u_char  ip_ttl;                 /* time to live                      */
        u_char  ip_p;                   /* protocol                          */
        u_short ip_sum;                 /* checksum                          */
        struct  in_addr ip_src,ip_dst;  /* source and dest address           */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp{
	u_short u_sport;		/* source port */
	u_short u_dport;		/* destination port */
	u_short u_len;		/* length */
	u_short u_sum;			/* checksum */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

/* https://www.itread01.com/p/122450.html */
static const char *mac2str(const u_char ether_addr_octet[ETHER_ADDR_LEN]) {
    static char a[18];
    int i;
    /* 將格式為 ehter_addr 格式的地址 ether_addr_octet 轉換成冒號分隔格式的 MAC 地址，並返回轉換後 MAC 地址的記憶體地址 */
    i = snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
    ether_addr_octet[0], ether_addr_octet[1],
    ether_addr_octet[2], ether_addr_octet[3],
    ether_addr_octet[4], ether_addr_octet[5]);
    return (i < 17 ? NULL : a);
}

/* 印出 16 進位的封包內容 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
	gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/* print packet payload data (avoid printing binary data) */
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/* dissect/print packet */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const u_char *payload;                  /* Packet payload */
	char timestr[5000];

	int size_ip;
	int size_tcp;
	int size_payload;

	printf(BOLDCYAN"\nPacket number %d:\n"RESET, count);
	count++;

	struct tm* ltime;
    ltime = localtime(&header->ts.tv_sec);
    strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", ltime);
	printf(BOLDYELLOW"   Time:  %s\n"RESET,timestr);


	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

        /* print source and destination MAC addresses */
        printf(BOLDBLUE"   MAC address:\n"RESET);
        printf("       From: %s\n", mac2str(ethernet->ether_shost));
        printf("         To: %s\n", mac2str(ethernet->ether_dhost));

        /* https://github.com/unikraft/lib-lwip/blob/staging/musl-imported/include/net/ethernet.h */
        /* 判斷 ether_type 是哪一種。 */
		if( ntohs(ethernet->ether_type) == ETHERTYPE_IP)
			printf(BOLDRED"        Ethernet type: IP\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_PUP)
			printf(BOLDRED"        Ethernet type: Xerox PUP\n"RESET);
        else if( ntohs(ethernet->ether_type) == ETHERTYPE_SPRITE)
			printf(BOLDRED"        Ethernet type: Sprite\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
			printf(BOLDRED"        Ethernet type: ARP\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_REVARP)
			printf(BOLDRED"        Ethernet type: Reverse ARP\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_AT)
			printf(BOLDRED"        Ethernet type: AppleTalk protocol\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_AARP)
			printf(BOLDRED"        Ethernet type: AppleTalk ARP\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_VLAN)
			printf(BOLDRED"        Ethernet type: IEEE 802.1Q VLAN tagging\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_IPX)
			printf(BOLDRED"        Ethernet type: IPX\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_IPV6)
			printf(BOLDRED"        Ethernet type: IP protocol version 6\n"RESET);
		else if( ntohs(ethernet->ether_type) == ETHERTYPE_LOOPBACK)
			printf(BOLDRED"        Ethernet type: Used to test interfaces \n"RESET);
	
    /* determine which protocol is used */
        printf(BOLDBLUE"   Protocal:"RESET);
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("  TCP\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("   Src : %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf("   Dst : %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			printf("   Payload (%d bytes)\n", size_payload);
			if (size_payload > 0)
                print_payload(payload, size_payload);
			return;
		case IPPROTO_UDP:
			printf("  UDP\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			printf("   Src : %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->u_sport));
			printf("   Dst : %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->u_dport));
			printf("   Payload (%d bytes)\n", ntohs(udp->u_len) - 8);
			return;
		case IPPROTO_ICMP:
			printf("  ICMP\n");
			return;
		case IPPROTO_IP:
			printf("  IP\n");
			return;
        case IPPROTO_OSPFIGP:
            printf("  OSPF\n");
            printf("   Src : %s\n", inet_ntoa(ip->ip_src));
			printf("   Dst : %s\n", inet_ntoa(ip->ip_dst));
            return;
		default:
			printf("  others , not defined\n");
			return;
	}

	return;
}

/* https://www.ibm.com/docs/en/aix/7.1?topic=pcl-sample-3-reading-previously-captured-packet-data-from-savefile-processing-it */
int main(int argc, char **argv) {

    pcap_t *p;                      /* packet capture descriptor                 */
    char ifname[IFSZ];              /* interface name (such as "en0")            */
    char filename[80];              /* name of savefile to read packet data from */

    char errbuf[PCAP_ERRBUF_SIZE];  /* buffer to hold error text                 */
    char prestr[80];                /* prefix string for errors from pcap_perror */
    
    int majver = 0, minver = 0;     /* major and minor numbers for the           */
                                    /* current Pcap library version              */

    if (argc < 2){
        fprintf(stderr, RED"[usage]: ./hw3 *.cap/*.pcap\n"RESET);
        exit(1);
    }

    strcpy(filename, argv[1]);

    /* open pcap file */
    if (!(p = pcap_open_offline(filename, errbuf))) {
        fprintf(stderr, RED"Error in opening savefile, %s, for reading: %s\n"RESET, filename, errbuf);
        exit(2);
    }

    /*
    * int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
    * 返回：成功傳回抓取封包的數量，失敗傳回-1，錯誤訊息從pcap_geterr()取得。
    * 參數：p一個libpcap handle。cnt抓取封包最多的數量，-1表示無限多。callback當抓取封包時要呼叫的函數。user要傳給callback的參數。
    * 功能：該函數利用callback的方式抓取封包，當抓取到封包時會呼叫callback函數，只有發生錯誤、抓到cnt數量或是在達到to_ms時間內都沒有封包時才會停止。
    */
    if (pcap_dispatch(p, 0, &got_packet, (u_char *)0) < 0) {
        /* pcap_dispatch 的 cnt 設為 0，代表會讀 packer 直到 EOF。 */
        sprintf(prestr, YELLOW"Error reading packets from interface %s"RESET, ifname);
        pcap_perror(p, prestr);
        exit(4);
    }
    else
        packets++;

    printf(GREEN"\nPackets read in: %d\n"RESET, packets);

    /*
    * Print out the major and minor version numbers. These are the version
    * numbers associated with this revision of the packet capture library.
    * The major and minor version numbers can be used to help determine
    * what revision of libpcap created the savefile, and, therefore, what
    * format was used when it was written.
    */

    if (!(majver = pcap_major_version(p))) {
        fprintf(stderr, RED"Error getting major version number from interface %s"RESET, ifname);
        exit(5);
    }
    printf("The major version number used to create the savefile was: %d.\n", majver);

    if (!(minver = pcap_minor_version(p))) {
        fprintf(stderr, RED"Error getting minor version number from interface %s"RESET, ifname);
        exit(6);
    }
    printf("The minor version number used to create the savefile was: %d.\n", minver);

    /*
    * Close the packet capture device and free the memory used by the
    * packet capture descriptor.
    */

    pcap_close(p);
	return 0;
}
