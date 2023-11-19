#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int c = 0;
char user_ip[16];

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;

    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
    char payload[1500];
};

// Structure to store information about each source IP
struct SourceIPInfo {
    char ip[16];
    int count;
};
#define MAX_SOURCE_IPS 100
struct SourceIPInfo sourceIPs[MAX_SOURCE_IPS];




struct BlackIP
{
    char blackIp[16];
};
#define MAX_BLACK_IPS 100
struct BlackIP blackIPs[MAX_BLACK_IPS];




// Function to find the index of a source IP in the array
int findSourceIPIndex(char* ip) {
    for (int i = 0; i < c; ++i) {
        if (strcmp(sourceIPs[i].ip, ip) == 0) {
            return i;
        }
    }
    return -1;  // Not found
}

int findBlackIPIndex(char* ip){
    for (int i = 0; i < c; ++i){
        if (strcmp(blackIPs[i].blackIp, ip) == 0){
            return i;
        }
    }
    return -1;
}


void print_payload(const char *payload, int length) {
    printf("    ");
    for (int i = 0; i < length; i++) {
        if (payload[i] == '\0') {
            break;
        }
        printf("%c", payload[i]);
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

        if (strcmp(inet_ntoa(ip->iph_destip), user_ip) == 0) {
            // Update source IP count
            int sourceIPIndex = findSourceIPIndex(inet_ntoa(ip->iph_sourceip));
            if (sourceIPIndex == -1) {
                // Source IP not found, add it to the array
                strcpy(sourceIPs[c].ip, inet_ntoa(ip->iph_sourceip));
                sourceIPs[c].count = 1;
                c++;
            } else {
                // Source IP found, increment the count
                sourceIPs[sourceIPIndex].count++;
                printf("\n%d\n", sourceIPs[sourceIPIndex].count);

                // Check if the count exceeds a threshold (e.g., 5)
                if (sourceIPs[sourceIPIndex].count > 1000) {
                    int blackIPIndex = findBlackIPIndex(inet_ntoa(ip->iph_sourceip));
                    if (blackIPIndex == -1){
                        char iptables_command[100]; // 충분한 크기로 조절
                        sprintf(iptables_command, "iptables -A INPUT -s %s -j DROP", inet_ntoa(ip->iph_sourceip));

                        int result = system(iptables_command);

                        if (result == 0) {
                            printf("Blocked IP successfully. -> %s\n", inet_ntoa(ip->iph_sourceip));
                            strcpy(blackIPs[c].blackIp, inet_ntoa(ip->iph_sourceip));
                        } else {
                            printf("Error blocking IP.\n");
                        }
                    }
                    else{
                        printf("\nOverlapped\n");
                    }
                }
            }
        }
    }
}

int main() {
    // My IP
    printf("Type your IP -> ");
    scanf("%s", user_ip);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error: ");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
