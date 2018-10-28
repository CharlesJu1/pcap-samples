
/* Compile with: gcc find_device.c -lpcap */
#include <ctype.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char **argv) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int timeout_limit = 1; /* In milliseconds */
    int promisc = 0;

     printf("11111 BUFSIZ=%d\n", BUFSIZ);
    /* Open device for live capture */
    handle = pcap_open_live(
            "en0",
            1500,
            promisc,
            timeout_limit,
            error_buffer
        );

     if (handle == NULL) {
        printf("error_buffer=%s \n", error_buffer);
        return 0;
     }

     u_char * callbk_str = (u_char *) "passed in str";
     pcap_loop(handle, 0, my_packet_handler, callbk_str);

    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    printf("args= %s\n", args);
    print_packet_info(packet, *packet_header);

    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", packet_header->caplen);
    printf("Expected packet size: %d bytes\n", packet_header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;


    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        //printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    //printf("TCP header length in bytes: %d\n", tcp_header_length);

    
    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = packet_header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    //printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            //printf("%d,", *temp_pointer);
            char c = *temp_pointer;
            if(isalpha(c) || isdigit(c))
                printf("%c", c);
            temp_pointer++;
        }
        printf("\n");
    }
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            //printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }

    printf("Finish processing a packet.\n\n");
    return;
}
