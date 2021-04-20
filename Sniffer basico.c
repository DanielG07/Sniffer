#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h> 
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/ioctl.h>

#define MAXIM 1524
#define MAXLINE 1024


char buffer[MAXIM];
int num;
int capturas = 0;
char red[MAXILINE];

struct ethhdr *header;
int ipv4=0, ipv6=0, arm=0, cdf=0, mac=0, ethernet=0, ieee=0;

void display_packet( char *buf, int n )
{
	unsigned char	ch;
	header = (struct ethhdr *)buffer;
	
	unsigned char des[6], src[6];
	__be16 proto = ntohs(header->h_proto);

	

	printf( "Paquete #%d\n", ++num );
	
	if(proto < 0x05DC && proto > 0x0000){
		ieee++;
		printf("IEEE 802.3\n");	
	}
	else if(proto >= 0x05DC){
		ethernet++;
		printf("Ethernet II\n");

		printf("Destino: ");

		for(int i = 0; i < 6; i++){
			des[i] = header->h_dest[i];
			printf("%02X ",des[i]);
		}

		printf("\nFuente: ");
		for(int i = 0; i < 6; i++){
			src[i] = header->h_source[i];
			printf("%02X ",src[i]);
		}

		printf( "\nLongitud de trama: %d bytes\n", n);

		printf( "Longitud carga util: %d bytes\n", n-14);

		printf("Proto: %04X",proto);
		if(proto == 0x0800){
			ipv4++;	
		}
		else if(proto == 0x86dd){
			ipv6++;
		}
		else if(proto == 0x0806){
			arm++;
		}
		else if(proto == 0x8808){
			cdf++;
		}
		else if(proto == 0x88E5){
			mac++;
		}

		int d = des[0] & 0x01;
		printf("\nDestino: ");
		if(d == 0x01){
			printf("Multicast\n");	
		}
		else if(d == 0x00){
			printf("Unicast\n");
		}

		int s = src[0] & 0x01;
		printf("Fuente: ");
		if(s == 0x01){
			printf("Multicast\n");	
		}
		else if(s == 0x00){
			printf("Unicast\n");
		}
	} 

	printf( "-------------------\n");
}

int main(){
	pthread_t id_hilo; 
	
	void *valor_retorno;
	int i=0;
	int s;

	printf("Nombre de la red: ");
	gets(red);
	fflush(stdin);

	printf("Cuantas tramas quiere analizar: ");
	scanf("%d",&capturas);

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	struct ifreq eth;
	
	strncpy(eth.ifr_name, red, IFNAMSIZ);
	if(ioctl(s, SIOCGIFFLAGS, &eth) < 0){
		perror("Error 1");
		exit(1);
	}
	

	eth.ifr_flags |= IFF_PROMISC;
	if(ioctl(s, SIOCSIFFLAGS, &eth) < 0){
		perror("Error 2");
		exit(1);
	}

	
	printf("\nMonitoring all packet on interface \'%s\' \n",red);
	
	do{
		int n = recvfrom(s, (char *)buffer, MAXIM, 0, NULL, NULL);
		display_packet( buffer, n );
	}while(num < capturas);

	printf("IPv4: %d\n",ipv4);
	printf("IPv6: %d\n",ipv6);
	printf("ARM: %d\n",arm);
	printf("CDF: %d\n",cdf);
	printf("MAC: %d\n",mac);

	printf( "-------------------\n");	
	
	printf("Ethernet II: %d\n",ethernet);
	printf("IEEE 802.3: %d\n",ieee);
	printf("Total analizado: %d\n",ethernet + ieee); 


	system("/sbin/ifconfig enp0s3 -promisc");
}
