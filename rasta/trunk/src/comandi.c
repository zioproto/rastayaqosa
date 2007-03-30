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


/*
until RSSI	Path cost
-50			100
-60			120
-70			140
-80			160
-100		200	
*/

void *comandi(void *in) // in ?
{
char command[50];
int record=3;
while (1)
{

//semaforo
sem_wait(&primo->mutex);

if (primo->next==NULL) //se non esiste un secondo record
{
	if (primo->MAC_AP[0] != 0xFF) //check che non sia il primo record vuoto
	{
	//bridge commands here
	
	if (!DISTRIBUTORE) {
	
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br0 wds0.49153 %d",primo->avgRSSI*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br0 ath3 %d",primo->avgRSSI*-2);
	if (DEBUG) printf("%s\n",command);
	}
	
	
	if (DISTRIBUTORE) {
	
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br5 wds0.49153.5 %d",primo->avgRSSIcolor5*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br5 ath3.5 %d",primo->avgRSSIcolor5*-2);
	if (DEBUG) printf("%s\n",command);
	system(command);
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br6 wds0.49153.6 %d",primo->avgRSSIcolor5*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br6 ath3.6 %d",primo->avgRSSIcolor5*-2);
	if (DEBUG) printf("%s\n",command);
	system(command);
	}
	
	
		//debug to display
		if (DEBUG) {
		
			if (BROADCOM) system("wl wds");
		
			if (DISTRIBUTORE) {
			system("brctl showstp br5");
			system("brctl showstp br6");
			}
		
		}
	}

}
else
{
	//bridge commands for first record here:
	
	if (!DISTRIBUTORE) {
	
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br0 wds0.49153 %d",primo->avgRSSI*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br5 ath3 %d",primo->avgRSSI*-2);
	if (DEBUG) printf("%s\n",command);
	system(command);
	}
	
	if (DISTRIBUTORE) {
	
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br5 wds0.49153.5 %d",primo->avgRSSIcolor5*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br5 ath3.5 %d",primo->avgRSSIcolor5*-2);
	printf("%s\n",command);
	system(command);
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br6 wds0.49153.6 %d",primo->avgRSSIcolor5*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br6 ath3.6 %d",primo->avgRSSIcolor5*-2);
	printf("%s\n",command);
	system(command);
	}
	
	//now we go on to the following records
	do
	{
	prec=prec->next;
	record=record+1;
	
	//bridge commands here
	
	if (!DISTRIBUTORE) {
	
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br0 wds0.49153 %d",prec->avgRSSI*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br5 ath3 %d",prec->avgRSSI*-2);
	if (DEBUG) printf("%s\n",command);
	system(command);
	}
	
	if (DISTRIBUTORE) {
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br5 wds0.4915%d.5 %d",record,prec->avgRSSIcolor5*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br5 ath%d.5 %d",record,prec->avgRSSIcolor5*-2);
	system(command);
	memset(command,0,50);
	if (BROADCOM) sprintf(command,"brctl setpathcost br6 wds0.4915%d.6 %d",record,prec->avgRSSIcolor6*-2);
	if (ATHEROS) sprintf(command,"brctl setpathcost br6 ath%d.6 %d",record,prec->avgRSSIcolor6*-2);
	system(command);
	}

	
	}
	while (prec->next!=NULL);
	prec=primo;
	succ=primo;
	record=3;
	
		
		//debug to display
		if (DEBUG) {
		
			if (BROADCOM) system("wl wds");
		
			if (DISTRIBUTORE) {
			system("brctl showstp br5");
			system("brctl showstp br6");
			}
		
		}
}


//semaforo
sem_post(&primo->mutex);
sleep(UPDATETIME);
}
return NULL;
}
