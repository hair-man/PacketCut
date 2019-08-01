#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <net/ethernet.h>

#define LIMITED_MAX_SIZE 65535
#define TCP_PKT_MAX_SIZE 1500

#define CONFIG_MTU 100

typedef struct _cksum_hdr
{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
}ckhdr_t;

//data - tcp头指针 or udp头指针
//flag - IPPROTO_TCP or IPPROTO_UDP 
//len  - tcp or udp数据长度 (ntohs(iph->tot_len) - iph->ihl << 2)
uint16_t tcp_or_udp_checksum(void* data, uint16_t len, uint32_t saddr, uint32_t daddr, uint32_t flag)
{
    uint32_t cksum = 0;
    uint16_t *buffer = NULL;
    uint16_t tmp = 0;
    
    int size =  0;

    struct udphdr* udp = NULL;
    struct tcphdr* tcp = NULL;
    ckhdr_t ckhdr = {0};

    switch(flag)
    {
        case IPPROTO_TCP:
            udp = (struct udphdr*)data;
            udp->check = 0;
            break;
        case IPPROTO_UDP:
            tcp = (struct tcphdr*)data;
            tcp->check = 0;
            break;
        default:
            return 0;
    } 

    ckhdr.saddr = saddr;
    ckhdr.daddr = daddr;
    ckhdr.proto = flag;
    ckhdr.len = htons(len);

    size = sizeof(ckhdr_t);
    buffer = (uint16_t*)&ckhdr;
    cksum = 0;

    while(size)
    {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    buffer = (uint16_t*)data;
    size = len;

    while(size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    if(size)
    {
        *(uint8_t*)&tmp = *(uint8_t*)buffer;
        cksum += tmp;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

uint16_t checksum(uint16_t* buf, uint32_t len)
{
    uint32_t cksum = 0;
    while(len > 1)
    {
        cksum += *buf++;
        len -= sizeof(uint16_t);
    }

    if(len)
        cksum += *(uint16_t*)buf;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

int tcp_pkt_cut(char* ori, int ori_len, char result_pkt[][TCP_PKT_MAX_SIZE], int result_pkt_len[], int* result_num, struct iphdr* iph, int iph_len)
{
    uint32_t seq = 0;

    char* data = NULL;
    int data_len = 0;

    struct tcphdr* tcpheader = NULL;
    int tcphdr_len = 0;

    int header_len = 0;

    int split_len = 0;
    int pkt_num = 0;

    int len = 0;

    tcpheader = (struct tcphdr*)((char*)iph + iph_len);
    tcphdr_len = tcpheader->doff << 2;

    header_len = sizeof(struct ether_header) + iph_len + tcphdr_len;
    data = ori + header_len;
    data_len = ori_len - header_len;

    *result_num = pkt_num;
    seq = ntohl(tcpheader->seq);

    while(data_len > split_len)
    {
        len = ((data_len - split_len) > (CONFIG_MTU - iph_len - tcphdr_len)) ? (CONFIG_MTU - iph_len - tcphdr_len) : (data_len - split_len);
        //拷贝头部
        memcpy(result_pkt[pkt_num], ori, header_len);
        //拷贝数据部分
        memcpy(result_pkt[pkt_num] + header_len, data + split_len, len);

        iph = (struct iphdr*)(result_pkt[pkt_num] + sizeof(struct ether_header));
        iph->tot_len = len + iph_len + tcphdr_len;
        
        result_pkt_len[pkt_num] = iph->tot_len + sizeof(struct ether_header);
        iph->tot_len = htons(iph->tot_len);

        //checksum
        iph->check = 0;
        iph->check = checksum((uint16_t*)iph, iph->ihl << 2);

        //fixed seq
        tcpheader = (struct tcphdr*)(result_pkt[pkt_num] + sizeof(struct ether_header) + iph_len);

        if((tcpheader->fin) && (data_len - split_len) > (CONFIG_MTU - iph_len - tcphdr_len))
        {
            tcpheader->fin = 0;
        }

        tcpheader->seq = htonl(seq + split_len);

        tcpheader->check = 0;

        tcpheader->check = tcp_or_udp_checksum(tcpheader, tcphdr_len, iph->saddr, iph->daddr, IPPROTO_TCP);

        pkt_num ++;

        split_len += len;
    }

    *result_num = pkt_num;
    return 0;
}

//
//ori - 原始数据(带以太头部的数据包)
//ori_len - 原始数据长度
//result_pkt - 存放分割后数据的数组
//result_pkt_len - 存放对应分割后数据的长度的数组
//result_num - 分割后的数据个数
//
int pkt_cut(char* ori,  int ori_len, char result_pkt[][TCP_PKT_MAX_SIZE], int result_pkt_len[], int* result_num)
{
    struct iphdr* iph = NULL;
    
    int iph_len = 0;

    if(ori_len > LIMITED_MAX_SIZE)
    {
        *result_num = 0;
        printf("pkt len [%d] over pkt limited max size [%d]\n", ori_len, LIMITED_MAX_SIZE);
        return -1;
    }

    iph = (struct iphdr*)(ori + sizeof(struct ether_header));
    iph_len = iph->ihl << 2;

    switch(iph->protocol)
    {
        case IPPROTO_TCP:
            tcp_pkt_cut(ori, ori_len, result_pkt, result_pkt_len, result_num, iph, iph_len);
            break;
        case IPPROTO_UDP:
            //udp_pkt_cur(); 
            break;
        default:
            return -1;
    }


    return 0;
}

int init_pcap_handle(char* device)
{
    pcap_t* handle = NULL;
    char err_buffer[256] = {0};

    //open device
    handle = pcap_open_live(device, 65535, 1, 0, err_buffer);
    if(handle == NULL)
    {
        printf("open device [%s] failed! err msg:[%s]\n", device, err_buffer);
        return -1;
    }
    printf("open device [%s] success!\n", device);

#if 1
    //set filter
    char filter[1024] = {0};

    uint32_t net = 0;
    uint32_t mask = 0;

    struct bpf_program fcode;
    
    if(0 != pcap_lookupnet(device, &net, &mask, err_buffer))
    {
        printf("lookup net failed! err msg:[%s]\n", err_buffer);
        return -1;
    }

    sprintf(filter + strlen(filter), "(ip and arp) or ");
    sprintf(filter + strlen(filter), "(not (dst net 192.168.1.0 mask 255.255.255.0) or dst host 192.168.1.251) and");
    sprintf(filter + strlen(filter), "(not (dst net 192.168.2.0 mask 255.255.255.0) or dst host 192.168.1.251)");

    if(0 != pcap_compile(handle, &fcode, filter, 0, mask))
    {
        printf("pcap compile filter [%s] failed! err msg: [%s]\n", filter, pcap_geterr(handle));
        return -1;
    }

    printf("pcap_compile success!\n");


    if(0 != pcap_setfilter(handle, &fcode))
    {
        printf("pcap handle set filter [%s] failed! err msg: [%s]\n", filter, pcap_geterr(handle));
        return -1;
    }

    printf("pcap_setfilter success!\n");

#endif

    //get pcap packet
    struct ether_header* eth = NULL;
    struct iphdr*        ipheader = NULL;
    char   sip[32] = {0};
    char   dip[32] = {0};

    int ret = 0;

    unsigned char* pkt = NULL;
    struct pcap_pkthdr* pkt_header = NULL;

    while((ret = pcap_next_ex(handle, &pkt_header, (const unsigned char**)&pkt)) >= 0)
    {
        printf("pkt comming!\n");

        eth = (struct ether_header*)pkt;
        switch(eth->ether_type)
        {
            case 0x0608:
                printf("arp");
                break;
            case 0x0008:
                ipheader = (struct iphdr*)(pkt + sizeof(struct ether_header));

                inet_ntop(AF_INET, &(ipheader->saddr), sip, sizeof(sip));
                inet_ntop(AF_INET, &(ipheader->daddr), dip, sizeof(dip));

                printf("[%s] - > - > - > [%s]\n", sip, dip);
                break;
        }
    }

    return 0;

}


int main(int argc, char**argv)
{

    printf("hello world!\n");

    if(argc != 2)
    {
        printf("eg. ./a.out eth0\n");
        return 0;
    }

    init_pcap_handle(argv[1]);

    return 0;
}
