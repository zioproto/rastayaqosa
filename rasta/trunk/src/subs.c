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

#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "../include/subs.h"

int send_eth(int sd, struct ethhdr *packet, char *device, int nbytes)
{
	if (write(sd, packet, nbytes)<0)
	{
		perror("write");
		return -1;
	}
#ifdef VERBOSE
	printf("Sending to %s : ",device);
	printf("Source = ");
	print_mac(packet->h_source);
	printf(" Destination = ");
	print_mac(packet->h_dest);
	printf("\n");
#endif
	return 1;
}

int send_tap( int sd, struct ethhdr *packet, char *device, int nbytes)
{
	unsigned char *buffer;

	buffer = malloc(nbytes + 2);
	
	memset(buffer, 0, nbytes + 2);
	memcpy((buffer+2), packet, nbytes);
	if(write(sd, buffer, nbytes + 2) < 0)
	{
		perror("write");
		return -1;
	}
#ifdef VERBOSE
	printf("Send to tap0 : ");
	printf("Source = ");
	print_mac(((struct ethhdr *)(buffer + 2))->h_source);
	printf(" Destination = ");
	print_mac(((struct ethhdr *)(buffer + 2))->h_dest);
	printf("\n");
#endif
	free(buffer);
	return 1;
}

int initialize(char *device, int sd, int promisc)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if(ioctl(sd, SIOCGIFFLAGS, &ifr)<0)
	{
		perror("SIOCGIFFLAGS");
		return -1;
	}
	if(promisc)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;
	if(ioctl(sd, SIOCSIFFLAGS, &ifr)<0)
	{
		perror("SIOCSIFFLAGS");
		return -1;
	}
#ifdef VERBOSE
	printf("Initialized device %s\n", device);
#endif
	if(ioctl(sd, SIOCGIFINDEX, &ifr)<0)
	{
		perror("SIOCGIFINDEX");
		return -1;
	}
	return ifr.ifr_ifindex;
}

void print_mac(unsigned char *mac)
{
	int i;

	printf("%x",mac[0]);
	for(i=1;i<ETH_ALEN;i++)
	{
		printf(":%x",mac[i]);
	}
}
