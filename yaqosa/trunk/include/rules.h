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

#ifndef RULES_H
#define RULES_H

struct rules {
  int rule_type; //MAC, IP, PORTA ...
  
  //mac Addresses
  unsigned char MAC1[6]; //sorgente
  unsigned char MAC2[6]; //destinazione
  
  //IP Addresses
  unsigned int saddr; /* indirizzo sorgente 32 bit */
  unsigned int daddr; /* indirizzo destinazione 32 bit */
  
  //Service Access Point SAP (ovvero protocollo di layer superiore indicato nel pacchetto IP)
  unsigned char SAP;
  
  //Port Number
  unsigned short port;
  
  //bridge di uscita 
  int output; 
  unsigned long int bw; //traffico generato dalla stazione (for future implemetations)
  
  struct timeval timeout;
  
  struct rules* next;
};

extern struct rules* primo_wlan;
extern struct rules* prec_wlan;
extern struct rules* succ_wlan;

extern int dynamic;

extern int debug;

extern unsigned long int br5bw;
extern unsigned long int br6bw; //controllo che non supero la max dimensione di un unsigned long

void addrule(int type,unsigned char *mac,unsigned int IP, unsigned short port,unsigned char SAP,int numerello,struct timeval timeout);
void delrule(int type,unsigned char *mac,unsigned int IP, unsigned short port,unsigned char SAP,int numerello,struct timeval timeout);



#endif
