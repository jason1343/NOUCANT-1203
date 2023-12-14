#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#define MAX_BLACKLIST_COMMANDS 5

char user_ip[16];
int iscommand;
int findSourceip;
int findBlackip;
char cmd[50];
int c = 0;
int b = 0;

//SourceIPs
struct SourceIP {
    char ip[16];
    int count;
};
#define MAX_SOURCE_IPS 100
struct SourceIP sourceIP[MAX_SOURCE_IPS];

//BlackIPs
struct BlackIP {
    char ip[16];
};
#define MAX_BLACK_IPS 100
struct BlackIP blackIP[MAX_BLACK_IPS];

//findSourceIPindex
int findSourceIPindex(char *ip) {
    for (int i = 0; i < c; ++i) {
        if (strcmp(sourceIP[i].ip, ip) == 0) {
            return i; //found.
        }
    }
    return -1; //not found, append it.
}

//findBlackIPindex
int findBlackIPindex(char *ip) {
    for (int i = 0; i < c; ++i) {
        if (strcmp(blackIP[i].ip, ip) == 0) {
            return 0; //exists, pass it.
        }
    }
    return -1; //not found, you must execute the command.
}


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

struct tcpheader{
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


int check_command(const char *payload, int length){
    char blackList[MAX_BLACKLIST_COMMANDS][10] = {"id","ls","whoami", "mkdir", "$"};
    for(int i = 0; i < MAX_BLACKLIST_COMMANDS; i++){
		if(strstr(payload, blackList[i]) != NULL){
			return 1;
    }
	}
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ethheader *eth = (struct ethheader *)packet;

	if (ntohs(eth->ether_type) == 0x0800) {
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
        if (strcmp(inet_ntoa(ip->iph_destip), user_ip) == 0) { 	
			findSourceip = findSourceIPindex(inet_ntoa(ip->iph_sourceip));
			if (findSourceip == -1) {
                strcpy(sourceIP[c].ip, inet_ntoa(ip->iph_sourceip));
                sourceIP[c].count = 1;
                c++;
            } else {
                sourceIP[findSourceip].count += 1;
                if (sourceIP[findSourceip].count > 1000) {
                    findBlackip = findBlackIPindex(inet_ntoa(ip->iph_sourceip));
                    if (findBlackip == -1) {
                        char cmd[100];
                        sprintf(cmd, "iptables -A INPUT -s %s -j DROP", inet_ntoa(ip->iph_sourceip));
                        int result = system(cmd);
                        if (result == 0) {
                            printf("Successfully blocked Sus ip -> %s\n", inet_ntoa(ip->iph_sourceip));
                            strcpy(blackIP[b].ip, inet_ntoa(ip->iph_sourceip));
                            b++;
                        } else {
                            printf("Failed to block\n");
                        }
                    } else {
                        // ¯\_(ツ)_/¯
                    }
                }

		    iscommand = check_command(tcp->payload, sizeof(tcp->payload));
			if(iscommand == 1){
				findBlackip = findBlackIPindex(inet_ntoa(ip->iph_sourceip));
				if (findBlackip == -1) {
                        char cmd[100];
                        sprintf(cmd, "iptables -A INPUT -s %s -j DROP", inet_ntoa(ip->iph_sourceip));
                        int result = system(cmd);
                        if (result == 0) {
                            printf("Successfully blocked Sus ip -> %s\nand payload -> %s\n", inet_ntoa(ip->iph_sourceip), tcp->payload);
                            strcpy(blackIP[b].ip, inet_ntoa(ip->iph_sourceip));
                            b++;
                        } else {
                            printf("Failed to block\n");
                        }
                    } else {
                        // ¯\_(ツ)_/¯
                    }
			}
        }
	}
	}
	usleep(1000);
}

void timeout() {
    for (int i = 0; i < c; ++i) {
        sourceIP[i].count = 0;
    }
    sleep(5);
}

void *got_packet_thread(void *arg) {
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

    return NULL;
}

void *timeout_thread(void *arg) {
    while (1) {
        timeout();
        sleep(5);
    }
    return NULL;
}

int main() {
    // My IP
    printf("Type your IP -> ");
    scanf("%s", user_ip);

    pthread_t gotPacketThreadId, timeoutThreadId;

    pthread_create(&gotPacketThreadId, NULL, got_packet_thread, NULL);

    pthread_create(&timeoutThreadId, NULL, timeout_thread, NULL);

    pthread_join(gotPacketThreadId, NULL);
    pthread_join(timeoutThreadId, NULL);

    return 0;
}
