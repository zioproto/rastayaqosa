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

/*
This file contains the code of 2 functions, addrule and delrule. The functions are used to add or remove a rule from the list of rules
*/


void addrule(int type,unsigned char *mac,unsigned int IP, unsigned short port,unsigned char SAP,int numerello,struct timeval timeout) {

if (primo_wlan->next==NULL)//se non esiste un secondo
			{ 
					//controllo se il primo è vuoto
				if (primo_wlan->rule_type == 0)
				{	//se si lo riempio
					
					
					switch (type) //if (type==1) //(!strcmp(name,"1")) 
					{
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
					case 1:
					primo_wlan->rule_type=1;
					memcpy(primo_wlan->MAC1,mac,sizeof(primo_wlan->MAC1));
					//memcpy((char *)(primo_wlan->output),(char *)value2,sizeof(primo_wlan->output));
					primo_wlan->output=numerello;
					//gettimeofday(&primo_wlan->timeout, 0);
					primo_wlan->timeout=timeout;
					break;
					
					case 2:
					primo_wlan->rule_type=2;
					memcpy(primo_wlan->MAC2,mac,sizeof(primo_wlan->MAC2));					
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 3:
					primo_wlan->rule_type=3;
					primo_wlan->saddr=IP;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 4:
					primo_wlan->rule_type=4;
					primo_wlan->saddr=IP;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 5:
					primo_wlan->rule_type=5;
					primo_wlan->SAP=0x06;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 6:
					primo_wlan->rule_type=6;
					primo_wlan->SAP=0x11;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 7:
					primo_wlan->rule_type=7;
					primo_wlan->SAP=0x06;
					primo_wlan->port=port;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					case 8:
					primo_wlan->rule_type=8;
					primo_wlan->SAP=0x11;
					primo_wlan->port=port;
					primo_wlan->output=numerello;					
					primo_wlan->timeout=timeout;
					break;
					
					
					}
					
				}
				else
				{ //se il primo è pieno
				succ_wlan=(struct rules*) malloc(sizeof(struct rules));	
				succ_wlan->next=NULL;
					
					switch (type) //if (type==1) //(!strcmp(name,"1")) 
					{
					case 1:
					succ_wlan->rule_type=1;
					memcpy((succ_wlan->MAC1),mac,sizeof(succ_wlan->MAC1));
					//memcpy((char *)(succ_wlan->output),(char *)value2,sizeof(succ_wlan->output));
					succ_wlan->output=numerello;
					succ_wlan->timeout=timeout;
					break;
					
					case 2:
					succ_wlan->rule_type=2;
					memcpy((succ_wlan->MAC2),mac,sizeof(succ_wlan->MAC2));
					succ_wlan->output=numerello;
					succ_wlan->timeout=timeout;
					break;
					
					case 3:
					succ_wlan->rule_type=3;
					succ_wlan->saddr=IP;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 4:
					succ_wlan->rule_type=4;
					succ_wlan->saddr=IP;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 5:
					succ_wlan->rule_type=5;
					succ_wlan->SAP=0x06;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 6:
					succ_wlan->rule_type=6;
					succ_wlan->SAP=0x11;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 7:
					succ_wlan->rule_type=7;
					succ_wlan->SAP=0x06;
					succ_wlan->port=port;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 8:
					succ_wlan->rule_type=8;
					succ_wlan->SAP=0x11;
					succ_wlan->port=port;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					}
				}
			}
			else //(se il primo e il secondo sono pieni) 
			{		
					do		{prec_wlan=prec_wlan->next;}
					while 	(prec_wlan->next!=NULL);
			
				
				succ_wlan=(struct rules*) malloc(sizeof(struct rules));
				succ_wlan->next=NULL;
				switch (type) //if (type==1) //(!strcmp(name,"1")) 
					{
					case 1:
					succ_wlan->rule_type=1;
					memcpy((succ_wlan->MAC1),mac,sizeof(succ_wlan->MAC1));
					//memcpy((char *)(succ_wlan->output),(char *)value2,sizeof(succ_wlan->output));
					succ_wlan->output=numerello;
					succ_wlan->timeout=timeout;
					break;
					
					case 2:
					succ_wlan->rule_type=2;
					memcpy((succ_wlan->MAC2),mac,sizeof(succ_wlan->MAC2));
					succ_wlan->output=numerello;
					succ_wlan->timeout=timeout;
					break;
					
					case 3:
					succ_wlan->rule_type=3;
					succ_wlan->saddr=IP;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 4:
					succ_wlan->rule_type=4;
					succ_wlan->saddr=IP;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 5:
					succ_wlan->rule_type=5;
					succ_wlan->SAP=0x06;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 6:
					succ_wlan->rule_type=6;
					succ_wlan->SAP=0x11;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 7:
					succ_wlan->rule_type=7;
					succ_wlan->SAP=0x06;
					succ_wlan->port=port;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					
					case 8:
					succ_wlan->rule_type=8;
					succ_wlan->SAP=0x11;
					succ_wlan->port=port;
					succ_wlan->output=numerello;					
					succ_wlan->timeout=timeout;
					break;
					}
			}
		prec_wlan=primo_wlan;
		succ_wlan=primo_wlan;
}

void delrule(int type,unsigned char *mac,unsigned int IP, unsigned short port,unsigned char SAP,int numerello,struct timeval timeout) {

switch (type){
case 1:

	if  ( !memcmp(mac, (char *)(primo_wlan->MAC1), 6 )) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( !memcmp(mac, (char *)(prec_wlan->MAC1), 6 )))
	{prec_wlan=prec_wlan->next;};

	if ( !memcmp(mac, (char *)(prec_wlan->MAC1), 6 ))
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 2:

	if  ( !memcmp(mac, (char *)(primo_wlan->MAC2), 6 )) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( !memcmp(mac, (char *)(prec_wlan->MAC2), 6 )))
	{prec_wlan=prec_wlan->next;};

	if ( !memcmp(mac, (char *)(prec_wlan->MAC2), 6 ))
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 3:
	
	if  ( primo_wlan->saddr == IP ) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->saddr == IP ))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->saddr == IP)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 4:

	if  ( primo_wlan->daddr == IP ) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->daddr == IP ))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->daddr == IP)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 5:

	if  ( primo_wlan->SAP == 0x06 ) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->SAP == 0x06 ))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->SAP == 0x06)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 6:

	if  ( primo_wlan->SAP == 0x11 ) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->SAP == 0x11 ))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->SAP == 0x11)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;

case 7:

	if  ( primo_wlan->SAP == 0x06 && primo_wlan->port == port) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->SAP == 0x06 && prec_wlan->port == port))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->SAP == 0x06 && prec_wlan->port == port)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;
	
case 8:

	if  ( primo_wlan->SAP == 0x11 && primo_wlan->port == port) {

	succ_wlan=primo_wlan->next;
	free(primo_wlan);
	primo_wlan = succ_wlan;
	prec_wlan = primo_wlan;
	}

	else{

	//questa while punta prec al nodo precedente di quello da eliminare
	while
	(prec_wlan->next->next!=NULL && ( prec_wlan->SAP == 0x11 && prec_wlan->port == port))
	{prec_wlan=prec_wlan->next;};

	if ( prec_wlan->SAP == 0x11 && prec_wlan->port == port)
	{
	succ_wlan=prec_wlan->next;
	prec_wlan->next=succ_wlan->next;
	free(succ_wlan);
	prec_wlan=primo_wlan;
	succ_wlan=primo_wlan;
	}
	else if (debug) printf("Errore, non ho cancellato niente dalla lista\n");} 
	break;

}//end switch
}//end void delrule
