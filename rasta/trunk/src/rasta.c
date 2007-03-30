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
#include <readconf.h>

/*moved to configuration file
#define BROADCOM 1
#define ATHEROS 0
#define myESSID "vito_saverio"
*/

struct statistica_link* primo;
struct statistica_link* prec ;
struct statistica_link* succ ;

int BROADCOM=0;
int ATHEROS=0;
int DISTRIBUTORE=0;
int DEBUG=1;
int UPDATETIME=10;

int BUFSIZE=1516;
double PESO=0.1;

char SNIFF_IFACE[10];
char myESSID[256];



int main(int argc , char **argv)
{
//threads
pthread_t collect_stats,execute_commands;
int res;
pthread_setconcurrency(2);

//vengono inizializzati i tre puntatori (1 solo adesso) a "statistica_link"
//(il tipo di dato creato nella struct in statistica.h). Questi serviranno a gestire la lista


primo = (struct statistica_link*) malloc(sizeof(struct statistica_link));
 
//inizializzo i semafori dei thread (va fatto ogni volta che si fa un malloc)
//if (sem_init(&primo.mutex,0,1) == -1 )  
if (sem_init(&primo->mutex,0,1) == -1 )  
{
perror("Non sono riuscito ad inizializzare i semafori");
exit(errno);
}

//leggo i files di configurazione
memset(SNIFF_IFACE,0,10);
memset(myESSID,0,256);
if (readconf() == -1) printf("Errore parsing configuration\n");

//sarebbe opportuno inserire qui un check sulla consistenza del file di configurazione, vedi idioti che selezionano BROADCOM e ATHEROS insieme.

if (DEBUG) printf("ESSID configurato %s\n",myESSID);


//Metto l'ap in monitor mode (broadcom && OpenWRT combo)
if (BROADCOM) system("wl -i eth1 monitor 1");

if (ATHEROS) 
{
if (DEBUG) printf("Executing script\n");
system("sh /etc/rasta/madwifi-ng.script");
/*
if (DEBUG) printf("Sto creando ath1 interfaccia di monitor\n");
system("wlanconfig ath1 create wlandev wifi0 wlanmode monitor");
if (DEBUG) printf("Sto tirando su ath1 con ifconfig\n");
//if (DEBUG) sleep(3);
system("ifconfig ath1 promisc up");
if (DEBUG) printf("Ho lanciato ifconfig, sembra tutto ok!\n");
*/
}

//inizializzo la lista dei WDS
primo->next = NULL;
//Setto questo tutti a 1 per riconoscerlo in un controllo che devo fare dopo
memset(primo->MAC_AP,255,6); //memset(variabile,valore,quantitàdibyte);
prec = primo;
succ = primo;
 
//creo i threads
res = pthread_create(&collect_stats,NULL,statistica, NULL);
if (res != 0)
{
perror("Errore nella creazione del thread");
exit(errno);
}

res = pthread_create(&execute_commands,NULL,comandi, NULL);
if (res != 0)
{
perror("Errore nella creazione del thread");
exit(errno);
}

pthread_join(execute_commands, NULL);
pthread_join(collect_stats, NULL);
return(0);
}
