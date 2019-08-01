#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <net/ethernet.h>


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
