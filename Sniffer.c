// Sniffer, donde vamos a analizar el datagrama ip.
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <semaphore.h>
#include <fcntl.h>

#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_ether.h>
 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/ioctl.h>

#define MAXIM 65536
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
struct iphdr *headerIP;
struct ethhdr *header;
char buffer[MAXIM];
struct sockaddr_in source,dest;

//Datos a guardar
int num = 0, n;
int ICMv4 = 0, IGMP = 0, IPv4 = 0, TCP = 0, UDP = 0, IPv6 = 0, OSPF = 0;
int tam159 = 0, tam639 = 0, tam1279 = 0, tam5119 = 0, mayor = 0;

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

	fprintf(puntero_archivo, "-------------------\n");
	fprintf(puntero_archivo,"ICMv4: %d\n",ICMv4);
	fprintf(puntero_archivo,"IGMP: %d\n",IGMP);
	fprintf(puntero_archivo,"IP: %d\n",IPv4);
	fprintf(puntero_archivo,"TCP: %d\n",TCP);
	fprintf(puntero_archivo,"UDP: %d\n",UDP);
	fprintf(puntero_archivo,"IPv6: %d\n",IPv6);
	fprintf(puntero_archivo,"OSPF: %d\n",OSPF);

	fprintf(puntero_archivo, "-------------------\n");
	fprintf(puntero_archivo,"Numero de paquetes:\n");
	fprintf(puntero_archivo,"0-159: %d\n",tam159);
	fprintf(puntero_archivo,"160-639: %d\n",tam639);
	fprintf(puntero_archivo,"640-1279: %d\n",tam1279);
	fprintf(puntero_archivo,"1279-5119: %d\n",tam5119);
	fprintf(puntero_archivo,"5120-mayor: %d\n",mayor);

	

	fclose(puntero_archivo);

	char fin[50] = "/sbin/ifconfig ";
	strcat(fin,red);
	strcat(fin," -promisc");
	system(fin);

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

		n = recvfrom(s, (char *)buffer, MAXIM, 0, NULL, NULL);

		sem_post(&sincronizador);
		//printf("%d\n",i);
		sleep(1);

	}
}

void *analizador(void* argument){
	
	header = (struct ethhdr *)(buffer);
	headerIP = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	//__be16 proto = ntohs(header->h_proto);
	
	sleep(3);
	printf("Analizador\n");
	i=0;
	while(i<capturas){
		sem_wait(&sincronizador);
		
		if(ntohs(header->h_proto) == 0x0800){
			fprintf(puntero_archivo, "Paquete #%d\n", ++num );
			fprintf(puntero_archivo,"Fuente: %02x.%02x.%02x.%02x\n",(unsigned char)buffer[26], (unsigned char)buffer[27], (unsigned char)buffer[28], (unsigned char)buffer[29]);
			fprintf(puntero_archivo,"Destino: %02x.%02x.%02x.%02x\n",(unsigned char)buffer[30], (unsigned char)buffer[31], (unsigned char)buffer[32], (unsigned char)buffer[33]);
			fprintf(puntero_archivo,"Header length %d bytes\n",((unsigned int)(headerIP->ihl))*4);
			fprintf(puntero_archivo,"Total length %d bytes\n",ntohs(headerIP->tot_len));
			fprintf(puntero_archivo,"Identification: 0x%02X%02x\n",(unsigned char)buffer[18],(unsigned char)buffer[19]);
			fprintf(puntero_archivo,"TTL: %d\n",(unsigned int)headerIP->ttl);
			if(headerIP->protocol == 0x01){
				fprintf(puntero_archivo,"Protocolo: ICMPv4 - 0x%02x\n",headerIP->protocol);
				ICMv4++;
			}
			else if(headerIP->protocol == 0x02){
				fprintf(puntero_archivo,"Protocolo: IGMP - 0x%02x\n",headerIP->protocol);
				IGMP++;
			}
			else if(headerIP->protocol == 0x04){
				fprintf(puntero_archivo,"Protocolo: IP - 0x%02x\n",headerIP->protocol);
				IPv4++;
			}
			else if(headerIP->protocol == 0x06){
				fprintf(puntero_archivo,"Protocolo: TCP - 0x%02x\n",headerIP->protocol);
				TCP++;
			}
			else if(headerIP->protocol == 0x11){
				fprintf(puntero_archivo,"Protocolo: UDP - 0x%02x\n",headerIP->protocol);
				UDP++;
			}
			else if(headerIP->protocol == 0x29){
				fprintf(puntero_archivo,"Protocolo: IPv6 - 0x%02x\n",headerIP->protocol);
				IPv6++;
			}
			else if(headerIP->protocol == 0x59){
				fprintf(puntero_archivo,"Protocolo: OSPF - 0x%02x\n",headerIP->protocol);
				OSPF++;
			}

			fprintf(puntero_archivo,"Carga util: %d bytes\n",ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4);
			
			if(ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4 < 160){
				tam159++;
			}
			else if(ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4 < 640){
				tam639++;
			}
			else if(ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4 < 1280){
				tam1279++;
			}
			else if(ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4 < 5120){
				tam5119++;
			}
			else if(ntohs(headerIP->tot_len)-((unsigned int)(headerIP->ihl))*4 >5119){
				mayor++;
			}

			int type = (unsigned int)headerIP->tos & 0xE0;

			if(type == 0x00){
				fprintf(puntero_archivo,"Tipo de servicio: De rutina -");
			}
			else if(type == 0x020){
				fprintf(puntero_archivo,"Tipo de servicio: Prioritario -");
			}
			else if(type == 0x40){
				fprintf(puntero_archivo,"Tipo de servicio: Inmediato -");
			}
			else if(type == 0x60){
				fprintf(puntero_archivo,"Tipo de servicio: Relampago -");
			}
			else if(type == 0x80){
				fprintf(puntero_archivo,"Tipo de servicio: Invalidacion relampago -");
			}
			else if(type == 0xA0){
				fprintf(puntero_archivo,"Tipo de servicio: Critico -");
			}
			else if(type == 0xC0){
				fprintf(puntero_archivo,"Tipo de servicio: Control de interred -");
			}
			else if(type == 0xE0){
				fprintf(puntero_archivo,"Tipo de servicio: Control de red -");
			}
			
			type = (unsigned int)headerIP->tos & 0x1E;
			if(type == 0x10){
				fprintf(puntero_archivo," Minimiza el retardo - 0x%02x\n",(unsigned int)headerIP->tos);
			}
			else if(type == 0x08){
				fprintf(puntero_archivo," Maximiza el rendimiento - 0x%02x\n",(unsigned int)headerIP->tos);
			}
			else if(type == 0x04){
				fprintf(puntero_archivo," Maximiza la fiabilidad - 0x%02x\n",(unsigned int)headerIP->tos);
			}
			else if(type == 0x02){
				fprintf(puntero_archivo," Minimiza el coste monetario - 0x%02x\n",(unsigned int)headerIP->tos);
			}
			else if(type == 0x00){
				fprintf(puntero_archivo," Servicio normal - 0x%02x\n",(unsigned int)headerIP->tos);
			}
			int isLast = 0;
			int isFragment = (unsigned int)headerIP->frag_off & 0xE0;
			if(isFragment == 0x20){
				fprintf(puntero_archivo,"Si esta fragmentado ");
				isLast = (unsigned int)buffer[21] & 0xFF;
				if(isLast > 0x00){
					fprintf(puntero_archivo,"y es intermedio - 0x%02x%02x\n",(unsigned int)buffer[20],(unsigned int)buffer[21]);
				}
				else{
					fprintf(puntero_archivo,"y es el primero - 0x%02x%02x\n",(unsigned int)buffer[20],(unsigned int)buffer[21]);
				}		
			}
			else{
				fprintf(puntero_archivo,"No esta fragmentado ");
				if(isLast > 0x00){
					fprintf(puntero_archivo,"y es el ultimo - 0x%02x%02x\n",(unsigned int)buffer[20],(unsigned int)buffer[21]);
				}
				else{
					fprintf(puntero_archivo,"y es el unico - 0x%02x%02x\n",(unsigned int)buffer[20],(unsigned int)buffer[21]);
				}
				
			}
			
			
			fprintf(puntero_archivo, "-------------------\n");
			i++;		
		}

		
		sem_post(&sincronizador);

		sleep(3);
	}
}








