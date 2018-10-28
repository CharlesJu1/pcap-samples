
/* Compile with: gcc find_device.c -lpcap */
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char **argv) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 1000; /* In milliseconds */

     printf("11111\n");
    /* Open device for live capture */
    handle = pcap_open_live(
            "en0",
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

     if (handle == NULL) {
        printf("error_buffer=%s \n", error_buffer);
        return 0;
     }
     printf("222222\n");
     /* Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, it will return NULL */
     packet = pcap_next(handle, &packet_header);
     if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    }

    /* Our function to output some info */
    print_packet_info(packet, packet_header);
    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
