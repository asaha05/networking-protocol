#include "arp.h"

char *allocate_str(int);
uint8_t *allocate_ustr(int);
void printpacketdetails(uint8_t[]);
int checkopcode(uint8_t[]);

int main(int argc, char **argv) {
    int i, status, frame_len, sd, bytes;
    char *interface, *target, *src_ip;
    arp_hdr arphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;

    src_mac = allocate_ustr(6);
    dst_mac = allocate_ustr(6);
    ether_frame = allocate_ustr(IP_MAXPACKET);
    interface = allocate_str(40);
    target = allocate_str(40);
    src_ip = allocate_str(INET_ADDRSTRLEN);

    strcpy(interface, "wlp2s0");

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
       perror("socket() failed to get socket descriptor for using ioctl()");
       exit(EXIT_FAILURE);
    } else {
       printf("YAY");
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

    if(ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
       perror("ioctl() failed to get source mac addr");
       return (EXIT_FAILURE);
    } 

    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));
    printf("\n%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    close(sd);

    memset(&device, 0, sizeof(device));
    if((device.sll_ifindex = if_nametoindex(interface)) == 0) {
    	perror("if_nametoindex failed to obtain interface index");
    }

    printf("Index for interface %s is %i\n\n\n", interface, device.sll_ifindex);

    memset(dst_mac, 0xff, 6 * sizeof (uint8_t));

    strcpy(src_ip, "172.11.12.184");
    strcpy(target, "172.11.12.101");

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
	    perror("error in inet_pton");
	    exit(EXIT_FAILURE);
    }

    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
          perror("error in getaddrinfo of target");
	  exit(EXIT_FAILURE);
    }

    ipv4 = (struct sockaddr_in *) res -> ai_addr;
    memcpy(&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof(uint8_t));
    freeaddrinfo(res);

    device.sll_family = AF_PACKET;
    memcpy(&device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    arphdr.htype = htons(1);
    arphdr.ptype = htons(ETH_P_IP);
    arphdr.hlen = 6;
    arphdr.plen = 4;
    arphdr.opcode = htons(ARP_OP_REQ);
    printf("Htype is %d\n", arphdr.htype);
    printf("Ptype is %d\n", arphdr.ptype);
    printf("Opcode is %d\n\n", arphdr.opcode);
    memcpy(&arphdr.sender_mac, src_mac, 6 * sizeof(uint8_t));

    memset(&arphdr.target_mac, 0, 6 * sizeof(uint8_t));
 
    frame_len = 6 + 6 + 2 + ARP_HDR_LEN;

    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    memcpy(ether_frame + ETH_HDR_LEN, &arphdr, ARP_HDR_LEN * sizeof(uint8_t));

    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket failed ..1");
	exit (EXIT_FAILURE);
    }

    if ((bytes = sendto(sd, ether_frame, frame_len, 0, (struct sockaddr*) &device, sizeof(device))) <= 0) {
	    perror("sendto() failed");
	    exit(EXIT_FAILURE);
     }

    uint8_t buf[frame_len];
    int ok;

    while(1) {
    	if ((bytes = recv(sd, buf, frame_len, 0)) < 0) {
        	 perror("recv failed!");
		 exit(EXIT_FAILURE);
   	 }
	ok = checkopcode(buf);
	if (ok == 1) {
	    printpacketdetails(buf);
	    break;
	}

    }

    close(sd);

    free(src_mac);
    free(dst_mac);
    free(ether_frame);
    free(interface);
    free(target);
    free(src_ip);

    return (EXIT_SUCCESS);
}

int checkopcode(uint8_t buf[]) {
	uint16_t* ptr;
	uint16_t opcode;
	ptr = (uint16_t*) (buf+20);
	opcode = *ptr;
	opcode = ntohs(opcode);
	if (opcode == ARP_OP_REPLY) {
	   return 1;
	} else {
	   return 0;
	}
}

void printpacketdetails(uint8_t buf[]) {
	printf("\nReceiving packet details...\n");
	printf("Dst mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	printf("Src mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);

	uint16_t* ptr;
	printf("Ethernet type : ..%.2x%.2x\n", buf[12], buf[13]);

	ptr = (uint16_t*) (buf+14);
	printf("Hardware type : %d\n", *ptr);

	ptr = (uint16_t*) (buf+16);
	printf("P type : %d\n", *ptr);

	printf("Hlen is : %d\n", buf[18]);
	
	ptr = (uint16_t*) (buf+20);
	printf("Opcode : %d\n", *ptr);

	printf("Src mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
	printf("src ip : %d.%d.%d.%d\n", buf[28], buf[29], buf[30], buf[31]);
        printf("Dst mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buf[32], buf[33], buf[34], buf[35], buf[36], buf[37]);
	printf("Dst ip : %d.%d.%d.%d\n\n", buf[38], buf[39], buf[40], buf[41]);

}



char * allocate_str (int len) {
  void *tmp;
  if (len <= 0) {
     printf("cannot allocate space for string");
     exit(EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof(char));
  if (tmp != NULL) {
     memset(tmp, 0, len * sizeof(char));
     return tmp;
  } else {
     printf("cannot allocate memory");
     exit(EXIT_FAILURE);
  }
}


uint8_t * allocate_ustr (int len) {
    void *tmp;
  if (len <= 0) {
     printf("cannot allocate space for string");
     exit(EXIT_FAILURE);
  }
  
  tmp = (char *) malloc (len * sizeof(uint8_t));
  if (tmp != NULL) {
     memset(tmp, 0, len * sizeof(uint8_t));
     return tmp;
  } else {
     printf("cannot allocate memory");
     exit(EXIT_FAILURE);
  }

}
