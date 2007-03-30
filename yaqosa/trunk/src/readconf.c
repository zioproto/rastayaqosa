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

#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> 

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include <rules.h>
#include <decisore.h>


int readconf() {
    
	printf("Reading configuration file\n");
	
	FILE * puntaconf;
	char buffer[100];
	char name[100];
	int type=0;
	char value1[100]; 
	//unsigned char value2[100];
	int numerello=0;
	puntaconf=fopen( "regole.conf", "r" );
	
	if( puntaconf  == NULL ) return(-1);
	
	while (fgets(buffer,100,puntaconf)!=NULL) 
	{
	 if (buffer[0] != '#') 
	 {	
		sscanf(buffer, "%d %s %d\n", &type,value1,&numerello);
		

			if (primo_wlan->next==NULL)//se non esiste un secondo
			{ 
					//controllo se il primo è vuoto
				if (primo_wlan->rule_type == 0)
				{	//se si lo riempio
					
					//if (type==1) //(!strcmp(name,"1"))  siamo passati a switch
					switch (type)
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
						memcpy(primo_wlan->MAC1,value1,sizeof(primo_wlan->MAC1));
						//memcpy((char *)(primo_wlan->output),(char *)value2,sizeof(primo_wlan->output));
						primo_wlan->output=numerello;
						//gettimeofday(&primo_wlan->timeout, 0);
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 2:
						primo_wlan->rule_type=2;
						memcpy(primo_wlan->MAC2,value1,sizeof(primo_wlan->MAC2));
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 3:
						primo_wlan->rule_type=3;
						primo_wlan->saddr=inet_addr((char*)value1);
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 4:
						primo_wlan->rule_type=4;
						primo_wlan->daddr=inet_addr((char*)value1);
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;

					case 5: 
						primo_wlan->rule_type=5;
						primo_wlan->SAP=0x06;						
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 6:
					    primo_wlan->rule_type=6;
						primo_wlan->SAP=0x11;					
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 7:
						primo_wlan->rule_type=7;
						primo_wlan->port=atoi(value1);
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						break;
						
					case 8:
						primo_wlan->rule_type=8;
						primo_wlan->port=atoi(value1);
						primo_wlan->output=numerello;						
						primo_wlan->timeout.tv_usec=0;
						//break;
					}
					
				}
				else
				{ //se il primo è pieno
				succ_wlan=(struct rules*) malloc(sizeof(struct rules));	
				succ_wlan->next=NULL;
				
					//if (type==1) //(!strcmp(name,"1")) 
					switch (type)
					{
					case 1:
					
						succ_wlan->rule_type=1;
						memcpy((succ_wlan->MAC1),value1,sizeof(succ_wlan->MAC1));
						//memcpy((char *)(succ_wlan->output),(char *)value2,sizeof(succ_wlan->output));
						succ_wlan->output=numerello;
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 2:
						
						succ_wlan->rule_type=2;
						memcpy((succ_wlan->MAC2),value1,sizeof(succ_wlan->MAC2));						
						succ_wlan->output=numerello;
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 3:
						succ_wlan->rule_type=3;
						succ_wlan->saddr=inet_addr((char*)value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 4:
						succ_wlan->rule_type=4;
						succ_wlan->daddr=inet_addr((char*)value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
					
					case 5: 
					
						succ_wlan->rule_type=5;
						succ_wlan->SAP=0x06;
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 6:
					        
						succ_wlan->rule_type=6;succ_wlan->rule_type=5;
						succ_wlan->SAP=0x11;
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
					
					case 7:
						succ_wlan->rule_type=7;
						succ_wlan->port=atoi(value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 8:
						succ_wlan->rule_type=8;
						succ_wlan->port=atoi(value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						//break;	
						
					}
				}
			}
			else //(se il primo e il secondo sono pieni) 
			{		
					do		{prec_wlan=prec_wlan->next;}
					while 	(prec_wlan->next!=NULL);
			
				
				succ_wlan=(struct rules*) malloc(sizeof(struct rules));
				succ_wlan->next=NULL;
				
				//if (type==1)//(!strcmp(name,"1")) siamo passati a switch
				switch (type)
					{
					case 1:
					
						succ_wlan->rule_type=1;
						memcpy((succ_wlan->MAC1),value1,sizeof(succ_wlan->MAC1));
						//memcpy((char *)(succ_wlan->output),(char *)value2,sizeof(succ_wlan->output));
						succ_wlan->output=numerello;
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 2:
						
						succ_wlan->rule_type=2;
						memcpy((succ_wlan->MAC2),value1,sizeof(succ_wlan->MAC2));						
						succ_wlan->output=numerello;
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 3:
						succ_wlan->rule_type=3;
						succ_wlan->saddr=inet_addr((char*)value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 4:
						succ_wlan->rule_type=4;
						succ_wlan->daddr=inet_addr((char*)value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
				    case 5: 
						succ_wlan->rule_type=5;
						succ_wlan->SAP=0x06;
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 6:
					    succ_wlan->rule_type=6;succ_wlan->rule_type=5;
						succ_wlan->SAP=0x11;
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
					
					case 7:
						succ_wlan->rule_type=7;
						succ_wlan->port=atoi(value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						break;
						
					case 8:
						succ_wlan->rule_type=8;
						succ_wlan->port=atoi(value1);
						succ_wlan->output=numerello;						
						succ_wlan->timeout.tv_usec=0;
						//break;				
					}
			}
		prec_wlan=primo_wlan;
		succ_wlan=primo_wlan;
	 }
 
	}
	
	
    fclose(puntaconf);
	//Debug
	printf("Configuration files read\n");
	
	
	//leggo il secondo file
	puntaconf=fopen( "distributore.conf", "r" );
	
	if( puntaconf  == NULL ) return(-1);
	
	while (fgets(buffer,100,puntaconf)!=NULL) 
	{
	    if (buffer[0] != '#') {
	
		sscanf(buffer, "%s %d\n", name,&numerello);
		
		if (!strcmp(name,"dynamic")) dynamic=numerello;
		if (!strcmp(name,"debug")) debug=numerello;
	}	
	}
	
	
    fclose(puntaconf);
	
	
    return 0;
    
}
