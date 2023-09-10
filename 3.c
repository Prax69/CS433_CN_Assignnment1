#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <ctype.h>
#include <time.h>

#define PACKET_BUFFER_SIZE 65536

int findProcessIDByPorts(int sourcePort) {
    char command[256];
    char buffer[256];
    FILE *output;

    // Create the 'lsof' command to list network connections
    sprintf(command, "lsof -i -n -P | grep ':%d'", sourcePort);

    // Execute the command and capture the output
    output = popen(command, "r");
    if (output == NULL) {
        perror("popen");
        return -1;
    }

    // Read and parse the output to get the PID
    while (fgets(buffer, sizeof(buffer), output) != NULL) {
        // Split the output line by spaces
        char *token = strtok(buffer, " ");
        while (token != NULL) {
            // Check if the token starts with a digit (PID)
            if (isdigit(token[0])) {
                int pid = atoi(token);
                pclose(output);  // Close the 'lsof' process
                return pid;
            }
            token = strtok(NULL, " ");
        }
    }

    pclose(output);  // Close the 'lsof' process
    return -1; // Process not found
}


int main() {
    int raw_socket;
    struct sockaddr server;
    socklen_t server_len = sizeof(server);
    unsigned char packet_buffer[PACKET_BUFFER_SIZE];

    // Create a raw socket to capture all packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1) {
        perror("Socket creation error");
        exit(1);
    }
    int arr[65536]={0};
    time_t start=time(NULL);
    // Receive packets and print information
    while (time(NULL)-start<=30) {
        int packet_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, &server, &server_len);
        if (packet_size == -1) {
            perror("Packet receive error");
            close(raw_socket);
            exit(1);
        }
	struct tcphdr *tcp_header = (struct tcphdr *)(packet_buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
	int port=ntohs(tcp_header->th_sport);
	int x=findProcessIDByPorts(port);
        if (x!=-1) arr[port]=x;
        else if (arr[port]==0) arr[port]=-1;
        printf("portno: %d, PID: %d\n",port,arr[port]);
    }
    close(raw_socket);
    
    int inp;
    while (1) {
	    printf("Give the desired port no: ");
	    scanf("%d",&inp);
	    printf("PID: %d\n",arr[inp]);
	}

    
    return 0;
}
