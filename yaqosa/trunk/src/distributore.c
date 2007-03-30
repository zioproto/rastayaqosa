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

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_tun.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <byteswap.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include <rules.h>
#include <decisore.h>
#include <readconf.h>

#define max(a,b) ((a)>(b) ? (a):(b))

//#######################################

//Puntatori per gestire le catene
struct rules* primo_wlan;
struct rules* prec_wlan;
struct rules* succ_wlan;

//Variabili che servono a gestire il comportamento del distrubutore
int dynamic=1;
int debug=1;

unsigned long int br5bw=0;
unsigned long int br6bw=0;

/* 
 * Allocate TUN device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */  
int tun_alloc(char *dev)
{
 struct ifreq ifr;
 int fd, err;

 if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
 return(0); //return tun_alloc_old(dev);
 
 memset(&ifr, 0, sizeof(ifr));
 /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
  *        IFF_TAP   - TAP device  
  *
  *        IFF_NO_PI - Do not provide packet information  
  */ 
 ifr.ifr_flags = IFF_TAP; 
 if( *dev )
 strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 
 if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
 close(fd);
 return err;
 }
 strcpy(dev, ifr.ifr_name);
 return fd;
}

//#######################################

int mytun_write(int fd, char *buf, int len)
{
    int wlen;
    return (wlen = write(fd, buf, len)) >=0 ? wlen : -1;
}

//#######################################

int mytun_read(int fd, char *buf, int len)
{
    int rlen;
    return (rlen = read(fd, buf, len)) >=0 ? rlen : -1;
}

//#######################################

int main(int argc, char *argv[])
{
    char buf[2048], dev1[10]="tap0", dev2[10]="tap1", dev3[10]="tap2";
    int fd1, fd2, fd3, len;
    int fm;
    //int count=0;
    struct timeval time;
    //struct iphdr *myiphdr;
    //struct ether_header *myether;
    fd_set fds;

    //inizializzo i puntatori che gestiscono le catene
    primo_wlan = (struct rules*) malloc(sizeof(struct rules));
    primo_wlan->rule_type=0;
    primo_wlan->next=NULL;
    succ_wlan = primo_wlan;
    prec_wlan = primo_wlan;
    
    printf("Please connect:\n");
    printf("tap0 at br0(wlan)\n");
    printf("tap1 at br5\n");
    printf("tap2 at br6\n\n");
    
    printf("Start Now!\n");
	
    if( (fd1 = tun_alloc(dev1)) < 0 ){
       printf("1:Cannot allocate TUN device 1\n");
       exit(1);
    }

    if( (fd2 = tun_alloc(dev2)) < 0 ){
       printf("1:Cannot allocate TUN device 2\n");
       exit(1);
    }

    if( (fd3 = tun_alloc(dev3)) < 0 ){
       printf("1:Cannot allocate TUN device 3\n");
       exit(1);
    }
    
    fm = max(fd1, fd2);
    fm = max(fm, fd3);

	readconf();
	if (debug) {
		printf("dynamic: %d\n",dynamic);
		
    }
	
    while(1){
		FD_ZERO(&fds);
        FD_SET(fd1, &fds);
        FD_SET(fd2, &fds);
        FD_SET(fd3, &fds);
        
        select(fm+1, &fds, NULL, NULL, NULL);
		
		gettimeofday(&time, 0);
		
        //wlan
        if( FD_ISSET(fd1, &fds) ) {
			if (debug) printf("Packet received from wlan\n");
			
            if( (len = mytun_read(fd1, buf, sizeof(buf))) < 0 ){
                printf("2:Error in mytun_read\n");
            } 
			else {
			//qui lancia decisore.c che restituisce un intero che uso con uno switch case per fare le mytun_write
			//ci devo passare anche len per aggiornare bw nella lista
				if (debug) printf("Decisore decide :%d\n",decisore(buf,len,time));
				switch (decisore(buf,len,time)) { 
					case 5:  
						mytun_write(fd2, buf, len);
						if (debug) printf("%d.%.06d: Received %d bytes from wlan -> br5\n", (int)time.tv_sec, (int)time.tv_usec, len);
						break;
					case 6:
						mytun_write(fd3, buf, len);
						if (debug) printf("%d.%.06d: Received %d bytes from wlan -> br6\n", (int)time.tv_sec, (int)time.tv_usec, len);
						break;
					
					    /* Codice spostato al decisore !
						if (dynamic) {
							if (debug)
								printf ("Dynamic=%d", dynamic);
							//modificare, usare br5bw e br6bw per decidere dove mandare il pacchetto
							mytun_write(fd3, buf, len);
							if (debug) printf("DEFAULT %d.%.06d: Received %d bytes from wlan -> br6\n", (int)time.tv_sec, (int)time.tv_usec, len);
						}*/
				}			
/* OLD CODE
                myether = (struct ether_header *) buf;
                myiphdr = (struct iphdr *) &buf[14];   
                if ((count%10) >= 5) {            
                    mytun_write(fd2, buf, len);
                    printf("%d.%.06d: Received %d bytes from wlan -> br5\n", (int)time.tv_sec, (int)time.tv_usec, len);
                    count++;
                } else {
                    mytun_write(fd3, buf, len);
                    printf("%d.%.06d: Received %d bytes from wlan -> br6\n", (int)time.tv_sec, (int)time.tv_usec, len);
                    count++;
                }
                    
		    printf("Tipo ether: %04X\n", bswap_16(myether->ether_type));
		    if(bswap_16(myether->ether_type)==0x8000)
                	printf("Tipo IP   : %d\n", (myiphdr->protocol));                  
*/
            }
        }

		//br5
        if( FD_ISSET(fd2, &fds) ) {
			if (debug) printf("PACCHETTO FROM br5\n");
            if( (len = mytun_read(fd2, buf, sizeof(buf))) < 0 ){
                printf("2:Error in mytun_read\n");
            } else {
                mytun_write(fd1, buf, len);
            }
       
            if (debug) printf("%d.%.06d: Received %d bytes from br5 -> wlan\n", (int)time.tv_sec, (int)time.tv_usec, len);            
        }
	
		//br6
        if( FD_ISSET(fd3, &fds) ) {
			if (debug) printf("PACCHETTO FROM br6\n");
            if( (len = mytun_read(fd3, buf, sizeof(buf))) < 0 ){
                printf("2:Error in mytun_read\n");
            } else {
                mytun_write(fd1, buf, len);
            }
       
            if (debug) printf("%d.%.06d: Received %d bytes from br6 -> wlan\n", (int)time.tv_sec, (int)time.tv_usec, len);
        }
     }
}
