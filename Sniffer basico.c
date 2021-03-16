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
char red[MAXLINE];

void display_packet( char *buf, int n )
{
	unsigned char	ch;

	printf( "\npacket #%d ", ++num );
	for (int i = 0; i < n; i+=16)
		{
		printf( "\n%04X: ", i );
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buf[ i+j ] : 0;
			if ( i + j < n ) printf( "%02X ", ch );
			else	printf( "   " );
			}
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buf[ i+j ] : ' ';
			if (( ch < 0x20 )||( ch > 0x7E )) ch = '.';
			printf( "%c", ch );
			}
		}
	printf( "\n%d bytes read\n-------\n", n );
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
		int n = recvfrom(s, (char *)buffer, MAXLINE, 0, NULL, NULL);
		display_packet( buffer, n );
	}while(num < capturas);

	
}
