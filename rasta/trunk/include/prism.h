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

#ifndef PRISM_H
#define PRISM_H

struct prism_hdr {
  u_int msg_code;
  u_int msg_length;
  char cap_device[16];  
};

struct prism_value {
  u_short did;
  u_short status1;
  u_short status2;
  u_short length;
  int value;
};

struct Frame_Control {
  unsigned char header; // contains type shown by ethereal 0x80 management ----- mentre 0x08 data
  unsigned char flags;
};

struct ieee8021qvirtualan { // 4 byte
/*non va  
  int Priority :3;
  int CFI :1;
  int ID :12;
  char pad[2];
 */
unsigned char info[2];
 
};

struct LLC {
  
  char paddafinire[6];
  unsigned short type;
};
//tra le parentesi dei char sono byte
  
struct prism {
	//Prism Header
	struct prism_hdr hdr;
	struct prism_value Host_Time;
	struct prism_value Mac_Time;
	char pad1[12];
	struct prism_value RSSI;
	struct prism_value SQ;
	char pad2[24];	
	struct prism_value Data_Rate;
	char pad3[12];
	struct prism_value Frame_Lenght;
	
	//ieee 802.11 header
	
	struct Frame_Control fc;		
	unsigned short Duration;	
	unsigned char MAC1[6]; //8*6=48
	unsigned char MAC2[6];
	unsigned char MAC3[6];
	//unsigned short Fragment_Number;
	unsigned short Sequence_Number;
	
	unsigned char MAC4[6]; // only if WDS !!!
	struct LLC llclayer; //unsigned char LLC[8];
	struct ieee8021qvirtualan vlan;
};
struct beacon {
	//Prism Header
	struct prism_hdr hdr;
	struct prism_value Host_Time;
	struct prism_value Mac_Time;
	char pad1[12];
	struct prism_value RSSI;
	struct prism_value SQ;
	char pad2[24];	
	struct prism_value Data_Rate;
	char pad3[12];
	struct prism_value Frame_Lenght;
	
	//ieee 802.11 header
	
	struct Frame_Control fc;		
	unsigned short Duration;	
	unsigned char MAC1[6]; //8*6=48 Destination
	unsigned char MAC2[6]; //source
	unsigned char MAC3[6]; //BSSID
	//unsigned short Fragment_Number;
	unsigned short Sequence_Number;
	
	//802.11 management frame
	unsigned char Fixed_Parameters[12];
	unsigned char Tagged_Parameters[52];
	/*
	char set; //deve essere 0x00
	char lenght; // in byte
	char ESSID
	*/
};

extern struct statistica_link* primo;
extern struct statistica_link* prec ;
extern struct statistica_link* succ ;

extern int BROADCOM;
extern int ATHEROS;
extern int DISTRIBUTORE;
extern int DEBUG;
extern int BUFSIZE;
extern double PESO;
extern int UPDATETIME;

extern char myESSID[256];
extern char SNIFF_IFACE[10];


#endif
