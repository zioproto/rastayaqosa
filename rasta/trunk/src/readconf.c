/*
RASTA - Radio Aware Spanning Tree Autoconfiguration
    Copyright (C) 2006  Francesco Saverio Proto

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

#include <prism.h>
#include <readconf.h>

#include <ctype.h>


int readconf() {
    
	printf("Reading rasta configuration file\n");
	
	FILE * puntaconf;
	char name[100];
	char buffer[100];
	char buffer2[100];
	int numerello=0;
	
	puntaconf=fopen( "/etc/rasta/rasta.conf", "r" );
	
	if( puntaconf  == NULL ) return(-1);
	
	while (fgets(buffer,100,puntaconf)!=NULL) 
	{
	    if ((buffer[0] != '#') && (!isspace(buffer[0]))) {
	
		sscanf(buffer, "%s %d\n", name,&numerello);
		//sscanf(buffer, "%s %s\n", name,buffer);
		
		if (!strcmp(name,"DEBUG")) DEBUG=numerello;
		if (!strcmp(name,"BROADCOM")) BROADCOM=numerello;
		if (!strcmp(name,"ATHEROS")) ATHEROS=numerello;
		if (!strcmp(name,"UPDATETIME")) UPDATETIME=numerello;
		if (!strcmp(name,"DISTRIBUTORE")) DISTRIBUTORE=numerello;
		if (!strcmp(name,"BUFSIZE")) BUFSIZE=numerello;
		if (!strcmp(name,"PESO")) PESO=numerello/10;
		
		}
	}
	
    fclose(puntaconf);
	
	puntaconf=fopen( "/etc/rasta/rasta.conf", "r" );
	
	if( puntaconf  == NULL ) return(-1);
	
	while (fgets(buffer,100,puntaconf)!=NULL) 
	{
	    if ((buffer[0] != '#') && (!isspace(buffer[0]))) {
	
		//sscanf(buffer, "%s %d\n", name,&numerello);
		sscanf(buffer, "%s %s\n", name,buffer2);
		
		if (!strcmp(name,"SNIFF_IFACE")) 
		{
		memcpy(SNIFF_IFACE,buffer2,sizeof(SNIFF_IFACE)); 
		printf("EXTRA DEBUG Sniff IFACE is set to %s\n",SNIFF_IFACE);
		}
		if (!strcmp(name,"myESSID")) memcpy(myESSID,buffer2,sizeof(myESSID)); 
		}
		memset(buffer,0,100);
	}	
	//Debug
	printf("Configuration files read\n");
	
    return 0;
    
}

