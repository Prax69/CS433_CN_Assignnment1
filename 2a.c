#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>

#define PCAP_FILE "3.pcap" // path to your pcap file or make sure it is in the same directory as your code

void process_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for reading
    handle = pcap_open_offline(PCAP_FILE, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Read and process packets
    pcap_loop(handle, 0, (pcap_handler)process_packet, NULL);

    // Close the pcap file
    pcap_close(handle);

    return 0;
}

void process_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Ethernet header is 14 bytes
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);  // IP header length varies

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to human-readable format
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Search for the keyword "Flag" in the packet payload
    const char *payload = (const char *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4);
    
    if (strstr(payload, "Flag") != NULL) {
        printf("Found 'Flag' keyword in packet payload:\n");
        printf("Source IP: %s\n", src_ip);
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination IP: %s\n", dest_ip);
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        printf("Payload Data:\n");

        // Print payload data, assuming it's ASCII text
        for (int i = 0; i < header->caplen; i++) {
            if (payload[i] >= 32 && payload[i] <= 126) {
                putchar(payload[i]);
            } else {
                putchar('.');
            }
        }
        printf("\n");
    }
}
