#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <semaphore.h>
#include <fcntl.h>

#include <arpa/inet.h> 
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/ioctl.h>

#define MAXIM 1524
#define MAXLINE 1024

//Funciones
void *analizador(void*argument);
void *capturador(void*argument);

//Para valores de red y #paquetes
int capturas = 0;
char red[MAXLINE];

//Semaforo
sem_t sincronizador;

//Socket
struct ethhdr *header;
char buffer[MAXIM];
char buffer1[MAXIM];

//Datos a guardar
int num = 0, n;
int ipv4=0, ipv6=0, arm=0, cdf=0, mac=0, ethernet=0, ieee=0;

//Utiles
int i = 0;

//Archivos
FILE* puntero_archivo;
char* nombre = "Registro.txt";

int main(){
	pthread_t analizadorHilo, capturadorHilo; 

	int i=0;

	printf("Nombre de la red: ");
	gets(red);
	fflush(stdin);

	printf("Cuantas tramas quiere analizar: ");
	scanf("%d",&capturas);

	sem_init(&sincronizador, 0, 1);

	if((puntero_archivo = fopen(nombre, "w")) == NULL){
		puts("ERROR EN LA OPERACION DE APERTURA");
		//return 1;
	}
	
	//fprintf(puntero_archivo,"a\n");

	if(pthread_create(&capturadorHilo, NULL, capturador,NULL)){
		printf("Problema en la creacion del hilo");
		exit(EXIT_FAILURE);
	}

	if(pthread_create(&analizadorHilo, NULL, analizador,NULL)){
		printf("Problema en la creacion del hilo");
		exit(EXIT_FAILURE);
	}

	pthread_join(capturadorHilo, NULL);
	pthread_join(analizadorHilo, NULL);

	sem_destroy(&sincronizador);
	
	//rewind(puntero_archivo);

	fprintf(puntero_archivo,"Total analizado: %d\n",ethernet + ieee);
	fprintf(puntero_archivo,"Ethernet II: %d\n",ethernet);
	fprintf(puntero_archivo,"IEEE 802.3: %d\n",ieee);

	fprintf(puntero_archivo, "-------------------\n");

	fprintf(puntero_archivo,"IPv4: %d\n",ipv4);
	fprintf(puntero_archivo,"IPv6: %d\n",ipv6);
	fprintf(puntero_archivo,"ARM: %d\n",arm);
	fprintf(puntero_archivo,"CDF: %d\n",cdf);
	fprintf(puntero_archivo,"MAC: %d\n",mac);

	

	fclose(puntero_archivo);


	system("/sbin/ifconfig enp0s3 -promisc");

	return 1;
}

void *capturador(void* argument){
	int s;
	unsigned char	ch;
	

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

	printf("Capturador\n");
	while(i < capturas){
		sem_wait(&sincronizador);
		
		n = recvfrom(s, (char*)buffer, MAXIM, 0, NULL, NULL);
		
		/*for (int i = 0; i < n; i+=16)
		{
		//Para visualizar paquetes en consola.
		printf( "\n%04X: ", i );
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buffer[ i+j ] : 0;
			if ( i + j < n ) printf( "%02X ", ch );
			else	printf( "   " );
			}
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buffer[ i+j ] : ' ';
			if (( ch < 0x20 )||( ch > 0x7E )) ch = '.';
			printf( "%c", ch );
			}
		}
	
		printf( "\n%d bytes read\n-------\n", n );*/

		
		sem_post(&sincronizador);
		//printf("%d\n",i);
		sleep(1);
		
	}
}

void *analizador(void* argument){
	
	header = (struct ethhdr *)buffer;
	
	unsigned char des[6], src[6];
	__be16 proto = ntohs(header->h_proto);

	
	sleep(3);
	printf("Analizador\n");
	for(i=0; i<capturas; i++){
		sem_wait(&sincronizador);
		
		fprintf(puntero_archivo, "Paquete #%d\n", ++num );
	
		if(ntohs(header->h_proto) < 0x05DC && ntohs(header->h_proto) > 0x0000){
			ieee++;
			fprintf(puntero_archivo,"IEEE 802.3\n");	
		}
		else if(ntohs(header->h_proto) >= 0x05DC){
			ethernet++;
			fprintf(puntero_archivo,"Ethernet II\n");

			fprintf(puntero_archivo,"Destino: ");

			for(int i = 0; i < 6; i++){
				des[i] = header->h_dest[i];
				fprintf(puntero_archivo,"%02X ",des[i]);
			}

			fprintf(puntero_archivo,"\nFuente: ");
			for(int i = 0; i < 6; i++){
				src[i] = header->h_source[i];
				fprintf(puntero_archivo,"%02X ",src[i]);
			}

			fprintf(puntero_archivo, "\nLongitud de trama: %d bytes\n", n);

			fprintf(puntero_archivo, "Longitud carga util: %d bytes\n", n-14);

			fprintf(puntero_archivo,"Proto: %04X",ntohs(header->h_proto));
			if(ntohs(header->h_proto) == 0x0800){
				ipv4++;	
			}
			else if(ntohs(header->h_proto) == 0x86dd){
				ipv6++;
			}
			else if(ntohs(header->h_proto) == 0x0806){
				arm++;
			}
			else if(ntohs(header->h_proto) == 0x8808){
				cdf++;
			}
			else if(ntohs(header->h_proto) == 0x88E5){
				mac++;
			}

			int d = des[0] & 0x01;
			fprintf(puntero_archivo,"\nDestino: ");
			if(d == 0x01){
				fprintf(puntero_archivo,"Multicast\n");	
			}
			else if(d == 0x00){
				fprintf(puntero_archivo,"Unicast\n");
			}

			int s = src[0] & 0x01;
			printf(puntero_archivo,"Fuente: ");
			if(s == 0x01){
				fprintf(puntero_archivo,"Multicast\n");	
			}
			else if(s == 0x00){
				fprintf(puntero_archivo,"Unicast\n");
			}

		} 

		fprintf(puntero_archivo, "-------------------\n");
		sem_post(&sincronizador);

		sleep(3);
	}
}








