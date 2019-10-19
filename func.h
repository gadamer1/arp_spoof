void store_ip(char* argv[],int len);
void get_my_info(char *dev);
void parseIP(uint8_t *result, char* source);
int make_and_send_packet(
	pcap_t * fp,
	uint8_t dest_mac[],
	uint8_t src_mac[],
	uint8_t sender_ip[],
	uint8_t target_ip[],
	uint8_t target_mac[],
	uint16_t opcode//request or reply
);
void broadcast_request(pcap_t * handle,bool check);
bool check_ip(uint8_t *ip,const u_char* check,bool isARP,bool isDest);

