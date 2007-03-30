/*
RASTA - Radio Aware Spanning Tree Autoconfiguration
    Copyright (C) 2006  Francesco Saverio Proto - Vito Ammirata

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

//threads
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>
#include <comandi.h>

#include <prism.h>
#include <subs.h>
#include <statistica.h>


#define MAXESSIDSIZE 256

/* moved to configuration file
#define BUFSIZE 1516
#define PESO 0.1
#define MAXESSIDSIZE 256

#define BROADCOM 1
#define ATHEROS 0
//prism0 o ath1
#define SNIFF_IFACE "prism0"
*/

void *statistica(void *in) // in ?
{
struct ethhdr *packet;
struct sockaddr_ll sock_ether;
struct prism *hdr;
struct beacon *beacon_sniffed;

unsigned char buf[BUFSIZE];

int bytes_received, eth_index;
int sd;
fd_set fds;

//flags per le if
int beacon_flag=0;
int data_flag=0;
int wds_flag=0;
int retry_flag=0;
int adhoc_flag=0;
int vlan_flag=0;

char ESSID[MAXESSIDSIZE]; 
unsigned char MACTEMP[7];
char command[50];

int record=3;

//statistiche generali per tutto l'AP
int bestRSSI=-100;
int worstRSSI=1;
int avgRSSI=0;


if (DEBUG) printf("Sniff IFACE is set to %s\n",SNIFF_IFACE);

//Let's open the raw socket with the sniffing interface
if((sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)
{
perror("socket");
exit(errno); //no return() perchè è un thread
}

if (DEBUG) printf("Checkpoint1\n");

if((eth_index = initialize(SNIFF_IFACE, sd, 1))<0)
{
exit(errno);
}

if (DEBUG) printf("Checkpoint2\n");

memset(&sock_ether, 0, sizeof(sock_ether));
sock_ether.sll_family = AF_PACKET;
sock_ether.sll_protocol = htons(ETH_P_ALL);
sock_ether.sll_ifindex = eth_index;

if(bind(sd, (struct sockaddr *)(&sock_ether), sizeof(sock_ether))<0)
{
perror("bind");
exit(errno);
}



while(1)
{
FD_ZERO(&fds);
FD_SET (sd, &fds);

if ((select(sd+1, &fds, NULL, NULL, NULL)) < 0)
{
perror ("select");
exit(errno);
}

if(FD_ISSET(sd, &fds))
{
if((bytes_received=read(sd, buf, sizeof buf))<0)
{
perror("read from ethernet failed");
exit(errno);
}
//Inserisco i dati del buffer nelle strutture per pescare le informazioni
packet = (struct ethhdr *)buf;
hdr = (struct prism *)buf;
beacon_sniffed = (struct beacon *)buf;

//Setto i vari flags analizzando il pacchetto:

//Data o Beacon?
/*
if (hdr->fc.header != 0x80 && hdr->fc.header != 0x08)
printf("WARNING, header type not known %02X\n",hdr->fc.header);
*/ 
 if (hdr->fc.header == 0x80) 
 beacon_flag=1;
else  
 beacon_flag=0;

 if (hdr->fc.header == 0x08) 
 data_flag=1;
else  
 data_flag=0;

 //controllo il bit retry (dovrei farlo solo per pacchetti data?)
if ((hdr->fc.flags | 0xF7) == 0xFF)
 retry_flag=1;
else
 retry_flag=0;

//Controllo bits toDS e fromDS per vedere di che tipo è il frame
if ((hdr->fc.flags | 0xFC) == 0xFF)
 wds_flag=1;
else 
 wds_flag=0;

 if ((hdr->fc.flags | 0xFC) == 0xFC) 
 adhoc_flag=1;
else 
 adhoc_flag=0;

//Controllo se il frame ha un tag vlan
if (hdr->llclayer.type == 0x0081) //zozzata, dovrebbe essere 8100, ma non faccio swap 
	vlan_flag=1;
else
	vlan_flag=0;

if (beacon_flag) 
{

if (DEBUG) printf("Entro in if beacon_flag\n");

//inserisco nella variabile di tipo string "ESSID" l'ESSID del beacon che sto processando
memset(ESSID,0,MAXESSIDSIZE);
memcpy(ESSID,&(beacon_sniffed->Tagged_Parameters[2]),beacon_sniffed->Tagged_Parameters[1]);

	if (!strcmp(ESSID,myESSID)) //controllo se è un beacon con ESSID uguale al mio
	{	
	
	if (DEBUG) printf("è arrivato un beacon uguale al mio\n");
	
	//Inserisco dentro MACTEMP il MAC dell'AP con ESSID uguale al mio, 

	memset(MACTEMP,0,7);
	MACTEMP[0]=beacon_sniffed->MAC2[0];
	MACTEMP[1]=beacon_sniffed->MAC2[1];
	MACTEMP[2]=beacon_sniffed->MAC2[2];
	MACTEMP[3]=beacon_sniffed->MAC2[3];
	MACTEMP[4]=beacon_sniffed->MAC2[4];
	MACTEMP[5]=beacon_sniffed->MAC2[5];	
	
	//ora devo controllare che non ho gia un WDS con lui e se no aggiungerlo ai miei WDS
	
	//semaforo
	if (DEBUG) printf("Aspetto il semafono\n");
	sem_wait(&(primo->mutex));
	
			if (primo->next==NULL)//se non esiste un secondo
			{ 
					//controllo se il primo è vuoto
					if (primo->MAC_AP[0] == 0xFF)
					{//se si lo riempio
					memset(primo->MAC_AP,0,7);										
					primo->MAC_AP[0]=MACTEMP[0];
					primo->MAC_AP[1]=MACTEMP[1];
					primo->MAC_AP[2]=MACTEMP[2];
					primo->MAC_AP[3]=MACTEMP[3];
					primo->MAC_AP[4]=MACTEMP[4];
					primo->MAC_AP[5]=MACTEMP[5];
				
					primo->bestRSSI=-100;
					primo->worstRSSI=1;
					primo->avgRSSI=0;
					primo->bestRSSIcolor5=-100;
					primo->worstRSSIcolor5=1;
					primo->avgRSSIcolor5=0;
					primo->bestRSSIcolor6=-100;
					primo->worstRSSIcolor6=1;
					primo->avgRSSIcolor6=0;
					primo->record_number=3;
					
					if (BROADCOM) 
					{
					memset(command,0,50);
					sprintf(command,"wl wds | wl wds %02X:%02X:%02X:%02X:%02X:%02X ",MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);
					system(command);
					}
					if (ATHEROS) 
					{
					memset(command,0,50);
					sprintf(command,"wlanconfig ath%d create wlandev wifi0 wlanmode wds",3);
					system(command);
					memset(command,0,50);
					sprintf(command,"iwpriv ath%d wds_add %02X:%02X:%02X:%02X:%02X:%02X ",3,MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);
					system(command);
					memset(command,0,50);
					sprintf(command,"iwpriv ath%d wds 1",3);
					system(command);
					//ifconfig ath1 up
					}
					
					}
			else
			{ //se il primo è pieno
						
					if( memcmp(primo->MAC_AP,MACTEMP,sizeof(primo->MAC_AP)) ) //check che non sia gia un WDS noto
					{
					succ=(struct statistica_link*) malloc(sizeof(struct statistica_link));
					if (sem_init(&succ->mutex,0,1) == -1 )  //va fatto ogni volta che si fa un malloc
					{
					perror("Non sono riuscito ad inizializzare i semafori");
					exit(errno);
					}
					memcpy(succ->MAC_AP,MACTEMP,7);
					succ->bestRSSI=-100;
					succ->worstRSSI=1;
					succ->avgRSSI=0;
					succ->bestRSSIcolor5=-100;
					succ->worstRSSIcolor5=1;
					succ->avgRSSIcolor5=0;
					succ->bestRSSIcolor6=-100;
					succ->worstRSSIcolor6=1;
					succ->avgRSSIcolor6=0;
					succ->record_number=4;
					
					
					if (BROADCOM)
					{
					memset(command,0,50);
					sprintf(command,"wl wds | wl wds %02X:%02X:%02X:%02X:%02X:%02X ",MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);					
					system(command);
					}
					
					if (ATHEROS)
					{					
					memset(command,0,50);
					sprintf(command,"wlanconfig ath%d create wlandev wifi0 wlanmode wds",4);
					system(command);
					memset(command,0,50);
					sprintf(command,"iwpriv ath%d wds_add %02X:%02X:%02X:%02X:%02X:%02X ",4,MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);
					system(command);
					memset(command,0,50);
					sprintf(command,"iwpriv ath%d wds 1",4);
					system(command);
					
					}
					primo->next=succ;
					succ->next=NULL;
					succ=primo;
					}
			}
			}
			else //(se il primo e il secondo sono pieni) 
			{		
					do
					{
					prec=prec->next;
					record=record+1;
						if (!memcmp(prec->MAC_AP,MACTEMP,sizeof(prec->MAC_AP)))
						{
						prec=primo;
						succ=primo;
						record=3;
						break;
						}
					}
					while (prec->next!=NULL);
			
				if (prec->next == NULL)
				{
				succ=(struct statistica_link*) malloc(sizeof(struct statistica_link));
				memcpy(succ->MAC_AP,MACTEMP,7);
				succ->bestRSSI=-100;
				succ->worstRSSI=1;
				succ->avgRSSI=0;
				succ->bestRSSIcolor5=-100;
				succ->worstRSSIcolor5=1;
				succ->avgRSSIcolor5=0;
				succ->bestRSSIcolor6=-100;
				succ->worstRSSIcolor6=1;
				succ->avgRSSIcolor6=0;
				succ->record_number=record;
				
				if (BROADCOM)
				{				
				memset(command,0,50);
				sprintf(command,"wl wds | wl wds %02X:%02X:%02X:%02X:%02X:%02X ",MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);				
				system(command);
				}
				if (ATHEROS)
				{
				memset(command,0,50);
				sprintf(command,"wlanconfig ath%d create wlandev wifi0 wlanmode wds",record);
				system(command);
				memset(command,0,50);
				sprintf(command,"iwpriv ath%d wds_add %02X:%02X:%02X:%02X:%02X:%02X ",record,MACTEMP[0],MACTEMP[1],MACTEMP[2],MACTEMP[3],MACTEMP[4],MACTEMP[5]);
				system(command);
				memset(command,0,50);
				sprintf(command,"iwpriv ath%d wds 1",record);
				system(command);
				}
				
				prec->next=succ;
				succ->next=NULL;
				prec=primo;
				succ=primo;
				record=3;
				}
				 
			}
		sem_post(&primo->mutex); //libero il semaforo
	}


//debug to display
if (DEBUG) {
printf("Beacon Received\n");
printf("Lenght of ESSID: %d\n",beacon_sniffed->Tagged_Parameters[1]);
printf("ESSID: %s\n",ESSID);
if (BROADCOM) system("wl wds");
printf("\n");
}

} //end if beacon_flag

if (wds_flag)
{
	//faccio i conti sull'RSSI generico, variabili globali non quelle nella lista a puntatori
	if (hdr->RSSI.value > bestRSSI) bestRSSI=hdr->RSSI.value;

	if (hdr->RSSI.value < worstRSSI) worstRSSI=hdr->RSSI.value;
	
	if (avgRSSI != 0) avgRSSI=avgRSSI*(1-PESO)+(hdr->RSSI.value*PESO);
	else avgRSSI=hdr->RSSI.value;
	
	//Metto in MACTEMP il MAC sorgente del pacchetto arrivato
    memset(MACTEMP,0,7);
    memcpy(MACTEMP,hdr->MAC2,6);
	
	if (primo->next==NULL)//se non esiste un secondo
			{ 
					if(!memcmp(primo->MAC_AP,MACTEMP,sizeof(primo->MAC_AP))) // se il primo record è gia quello giusto
					{
						if (hdr->RSSI.value > primo->bestRSSI) primo->bestRSSI=hdr->RSSI.value;
						if (hdr->RSSI.value < primo->worstRSSI) primo->worstRSSI=hdr->RSSI.value;
	
						if (primo->avgRSSI != 0) primo->avgRSSI=primo->avgRSSI*(1-PESO)+(hdr->RSSI.value*PESO);
						else primo->avgRSSI=hdr->RSSI.value;
					
						if (vlan_flag)
						{
							if (hdr->vlan.info[1] == 0x05)
							{
								if (hdr->RSSI.value > primo->bestRSSIcolor5) primo->bestRSSIcolor5=hdr->RSSI.value;
								if (hdr->RSSI.value < primo->worstRSSIcolor5) primo->worstRSSIcolor5=hdr->RSSI.value;
	
								if (primo->avgRSSIcolor5 != 0) primo->avgRSSIcolor5=primo->avgRSSIcolor5*(1-PESO)+(hdr->RSSI.value*PESO);
								else primo->avgRSSIcolor5=hdr->RSSI.value;
							}
	
							if (hdr->vlan.info[1] == 0x06)
							{
								if (hdr->RSSI.value > primo->bestRSSIcolor6) primo->bestRSSIcolor6=hdr->RSSI.value;
								if (hdr->RSSI.value < primo->worstRSSIcolor6) primo->worstRSSIcolor6=hdr->RSSI.value;
	
								if (primo->avgRSSIcolor6 != 0) primo->avgRSSIcolor6=primo->avgRSSIcolor6*(1-PESO)+(hdr->RSSI.value*PESO);
								else primo->avgRSSIcolor6=hdr->RSSI.value;
							}
							
							
						}					
					}
			
			}
			else //(se il primo non è quello giusto)
			{		
					do
					{
					prec=prec->next;
						if (!memcmp(prec->MAC_AP,MACTEMP,sizeof(prec->MAC_AP)))
						{
							if (hdr->RSSI.value > prec->bestRSSI) prec->bestRSSI=hdr->RSSI.value;
							if (hdr->RSSI.value < prec->worstRSSI) prec->worstRSSI=hdr->RSSI.value;
	
							if (prec->avgRSSI != 0) prec->avgRSSI=prec->avgRSSI*(1-PESO)+(hdr->RSSI.value*PESO);
							else prec->avgRSSI=hdr->RSSI.value;
					
							if (vlan_flag)
							{
								if (hdr->vlan.info[1] == 0x05)
								{
									if (hdr->RSSI.value > prec->bestRSSIcolor5) prec->bestRSSIcolor5=hdr->RSSI.value;
									if (hdr->RSSI.value < prec->worstRSSIcolor5) prec->worstRSSIcolor5=hdr->RSSI.value;
	
									if (prec->avgRSSIcolor5 != 0) prec->avgRSSIcolor5=prec->avgRSSIcolor5*(1-PESO)+(hdr->RSSI.value*PESO);
									else prec->avgRSSIcolor5=hdr->RSSI.value;
								}
							
							
								if (hdr->vlan.info[1] == 0x06)
								{
									if (hdr->RSSI.value > prec->bestRSSIcolor6) prec->bestRSSIcolor6=hdr->RSSI.value;
									if (hdr->RSSI.value < prec->worstRSSIcolor6) prec->worstRSSIcolor6=hdr->RSSI.value;	
									if (prec->avgRSSIcolor6 != 0) prec->avgRSSIcolor6=prec->avgRSSIcolor6*(1-PESO)+(hdr->RSSI.value*PESO);
									else prec->avgRSSIcolor6=hdr->RSSI.value;
								}							
							}						
							prec=primo;
							succ=primo;
							break;
						}
					}
					while (prec->next!=NULL);	
				prec=primo;
				succ=primo;
			}
/* if (DEBUG) {
//debug to display
printf("---------------------\n");
printf("Best RSSI is: %d\n", bestRSSI);
printf("Worst RSSI is: %d\n", worstRSSI);
printf("Average RSSI is: %d\n", avgRSSI);

printf("Bytes Received");
printf("  %d\n\n", bytes_received);

//controllo il bit retry
if (retry_flag) printf("Frame is a Retrasmission\n");
//debug printf("hdr->llclayer.type %04X\n",hdr->llclayer.type);
if (vlan_flag) printf("Frame is vlan tagged of color %02X%02X\n",hdr->vlan.info[0],hdr->vlan.info[1]);

// debug printf("Header: 08 è Data, 80 è Mng, io ho letto %02X\n",hdr->fc.header);
printf("RSSI");
printf("  %d\n\n", hdr->RSSI.value);

printf("Data Rate");
printf("  %d\n\n", hdr->Data_Rate.value);

printf("Receiver MAC Address");
printf("  %02X:%02X:%02X:%02X:%02X:%02X\n\n", hdr->MAC1[0], hdr->MAC1[1], hdr->MAC1[2], hdr->MAC1[3], hdr->MAC1[4], hdr->MAC1[5]);
printf("Transmitter MAC Address");
printf("  %02X:%02X:%02X:%02X:%02X:%02X\n\n", hdr->MAC2[0], hdr->MAC2[1], hdr->MAC2[2], hdr->MAC2[3], hdr->MAC2[4], hdr->MAC2[5]);
printf("3rd MAC Address");
printf("  %02X:%02X:%02X:%02X:%02X:%02X\n\n", hdr->MAC3[0], hdr->MAC3[1], hdr->MAC3[2], hdr->MAC3[3], hdr->MAC3[4], hdr->MAC3[5]);
printf("4th MAC Address");
printf("  %02X:%02X:%02X:%02X:%02X:%02X\n\n", hdr->MAC4[0], hdr->MAC4[1], hdr->MAC4[2], hdr->MAC4[3], hdr->MAC4[4], hdr->MAC4[5]);

printf("Sequence Number");
printf("  %d\n", hdr->Sequence_Number);
}
*/
} //end if wds_flag

}
} //end while(1)
return NULL;
}
