/*
YaQoSa - Yet Another Quality Of Service Approach
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

#include <rules.h>
#include <decisore.h>
#include <readconf.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <byteswap.h>

#define TIMEOUT 180

/*  note per il programmatore:
Questa funzione deve prendere in ingresso il buffer contentente tutto il frame per poter prendere una decisione su questo
la catena di regole se la prende in automatico senza che si passa perchè è extern 
*/


/* Exit Codes:
-1 errore
 0 non fai niente,
gli altri valori del return sono il numero della vlan su cui deve uscire il pacchetto
*/

int decisore(char *buf,int len,struct timeval timenow) {
	struct iphdr *myiphdr;
	struct ether_header *myether;
	
	struct tcphdr *mytcphdr;
	struct udphdr *myudphdr;

	myether = (struct ether_header *) buf;
	myiphdr = (struct iphdr *) &buf[14];
	mytcphdr = (struct tcphdr *) &buf[14+20];
	myudphdr = (struct udphdr *) &buf[14+20];
		
		/*Mappatura regole(valore di prec_wlan->rule_type):
		
		1: check sul Mac Address Sorgente
		2: check sul Mac Address Destinazione
		3: check sull'IP Sorgente
		4: check sull'IP Destinazione
		5: check su essere TCP
		6: check su essere UDP
		7: porta TCP specifica
		8: porta UDP specifica
		*/
		
		
	//controllo se il primo è vuoto
	
	/* Non ha senso uscire se il primo è vuoto, devo comunque arrivare al codice "dynamic"
	if (primo_wlan->rule_type == 0) {	
		//se è vuoto non ci sono regole ed esco senza fare nulla
		
		return(0);	
	}
        */
	
		
	//se il primo è pieno vedo la regola
	//if (primo_wlan->rule_type == 1) siamo passati allo switch
	switch (primo_wlan->rule_type)
	{	
		//se è 0 significa che il primo è vuoto
		case 0:
		break;
		
		case 1:
		if ( !memcmp((char *)(myether->ether_shost), (char *)(primo_wlan->MAC1), 6 )) {
			
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(1,primo_wlan->MAC1,(unsigned int)NULL,(unsigned int)NULL,(char)NULL,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					};
			};
			
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		}
		break;
	    
		case 2:
		if ( !memcmp((char *)(myether->ether_dhost), (char *)(primo_wlan->MAC2), 6 )) {
			
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(1,primo_wlan->MAC2,(unsigned int)NULL,(unsigned short)NULL,(char)NULL,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					};
			};
			
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		}
		break;

		case 3:
		if (primo_wlan->saddr == myiphdr->saddr) {
		
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(3,NULL,primo_wlan->saddr,(unsigned short)NULL,(char)NULL,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		} 
		break;
		
		case 4:
		if (primo_wlan->daddr == myiphdr->daddr) {
		
		if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(4,NULL,primo_wlan->daddr,(unsigned short)NULL,(char)NULL,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		}
		break;
		
		case 5:
		if (primo_wlan->SAP == 0x06) {
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(5,NULL,(int)NULL,(unsigned short)NULL,0x06,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		}
		break;
		
		case 6:
		if (primo_wlan->SAP == 0x11) {
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(6,NULL,(int)NULL,(unsigned short)NULL,0x11,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		
		}
		break;
		
		case 7:
		if ( (primo_wlan->SAP == 0x06) && (primo_wlan->port == mytcphdr->dest) ) {
		
			if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(7,NULL,(int)NULL,primo_wlan->port,0x06,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		
		}
		break;
		
		case 8:
		if (primo_wlan->SAP == 0x11 && primo_wlan->port == myudphdr->dest) {
		
		if (primo_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-primo_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(8,NULL,(int)NULL,primo_wlan->port,0x11,primo_wlan->output,primo_wlan->timeout);
				}
				else {
					if (primo_wlan->output == 5) 
						br5bw+=len;
					if (primo_wlan->output == 6) 
						br5bw+=len;
					return(primo_wlan->output); 
					}
			}
			if (primo_wlan->timeout.tv_usec==0) {
			
				if (primo_wlan->output == 5) 
					br5bw+=len;
				if (primo_wlan->output == 6) 
					br5bw+=len;
				return(primo_wlan->output);
			}
		
		}
		break;
		
		
	} // end switch
	
	//records successivi al primo
	while 	(prec_wlan->next!=NULL)	{
		prec_wlan=prec_wlan->next;
	
		//if (prec_wlan->rule_type == 1) siamo passati allo switch
		
		switch (prec_wlan->rule_type) {
		case 1:
			if ( !memcmp((char *)(myether->ether_shost),(char *)prec_wlan->MAC1, 6) ) {
			
					if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
						if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
							delrule(1,prec_wlan->MAC1,(unsigned int)NULL,(unsigned int)NULL,(char)NULL,prec_wlan->output,prec_wlan->timeout);
						}
						else {
							if (prec_wlan->output == 5) 
								br5bw+=len;
							if (prec_wlan->output == 6) 
								br5bw+=len;
							return(prec_wlan->output); 
						};
					};
			
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
			}
		case 2:
			if ( !memcmp((char *)(myether->ether_dhost),(char *)prec_wlan->MAC2, 6) ) {
			
					if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
						if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
							delrule(1,prec_wlan->MAC2,(unsigned int)NULL,(unsigned int)NULL,(char)NULL,prec_wlan->output,prec_wlan->timeout);
						}
						else {
							if (prec_wlan->output == 5) 
								br5bw+=len;
							if (prec_wlan->output == 6) 
								br5bw+=len;
							return(prec_wlan->output); 
						};
					};
			
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
			}
		case 3:
		if (prec_wlan->saddr == myiphdr->saddr) {
		
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(3,NULL,prec_wlan->saddr,(unsigned int)NULL,(char)NULL,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		}
		case 4:
		if (prec_wlan->daddr == myiphdr->daddr) {
		
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(4,NULL,prec_wlan->daddr,(unsigned int)NULL,(char)NULL,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		}
		break;
		
		case 5:
		if (prec_wlan->SAP == 0x06) {
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(4,NULL,(int)NULL,(unsigned int)NULL,0x06,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		}
		break;
		
		case 6:
		if (prec_wlan->SAP == 0x11) {
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(5,NULL,(int)NULL,(unsigned int)NULL,0x11,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		
		}
		break;
		
		case 7:
		if ( (prec_wlan->SAP == 0x06) && (prec_wlan->port == mytcphdr->dest) ) {
		//if(1){
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(7,NULL,(int)NULL,prec_wlan->port,0x06,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		
		}
		break;
		
		case 8:
		if (prec_wlan->SAP == 0x11 && prec_wlan->port == myudphdr->dest) {
		//if(1){	
			if (prec_wlan->timeout.tv_usec!=0) { /*è una regola aggiunta dinamicamente quindi fare qualcosa*/ 
			
				if ( timenow.tv_sec-prec_wlan->timeout.tv_sec>TIMEOUT) {
									delrule(8,NULL,(int)NULL,prec_wlan->port,0x11,prec_wlan->output,prec_wlan->timeout);
				}
				else {
					if (prec_wlan->output == 5) 
						br5bw+=len;
					if (prec_wlan->output == 6) 
						br5bw+=len;
					return(prec_wlan->output); 
					}
			}
			if (prec_wlan->timeout.tv_usec==0) {
			
				if (prec_wlan->output == 5) 
					br5bw+=len;
				if (prec_wlan->output == 6) 
					br5bw+=len;
				return(prec_wlan->output);
			}
		
		}
		break;
		
		} //end switch
	} //end while
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;			

	//Se arrivi fino a qui non hai matchato nessuna regola, o la regola che hai matchato era scaduta ed è stata cancellata, se è impostata la modalità dynamic vediamo cosa fare del frame
	
	if (dynamic) {
			    if (debug)
				    printf ("Dynamic=%d\n", dynamic);
					
				//usare br5bw e br6bw per decidere dove mandare il pacchetto
				if (br5bw<br6bw) {
				addrule(1,myether->ether_shost,(unsigned int)NULL,(unsigned int)NULL,(char)NULL,5,timenow);
				if (debug) printf("RULE ADDED!! - The Received bytes from wlan -> br5\n");
				return(5);
				}
				else{
				addrule(1,myether->ether_shost,(unsigned int)NULL,(unsigned int)NULL,(char)NULL,6,timenow);
				if (debug) printf("RULE ADDED!! - Received bytes from wlan -> br6\n");
				return(6);
				}
				
				
				}

//debug to display
	if (debug) 
		printf("Tipo ether: %04X\n", bswap_16(myether->ether_type));
	if (debug){
		if (bswap_16(myether->ether_type)==0x8000) 
			printf("Tipo IP   : %d\n", (myiphdr->protocol));  
	}
	return(0);				
}

	

