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

#ifndef STATISTICA_H
#define STATISTICA_H

#include <syslog.h>

void *statistica(void *);

/*
viene creato il tipo di dato che deve contenere i dati
e il puntatore al dato successivo
*/

struct statistica_link {
    //char MAC_AP[6];
    unsigned char MAC_AP[7]; //mi conviene farli da 7 cosi li uso come stringhe con il carattere 0 alla fine
    int record_number; //starts from "3"
	
	//statiche generali link
    int bestRSSI;
    int worstRSSI;
    int avgRSSI;

    //statistiche colore 5
    int bestRSSIcolor5;
    int worstRSSIcolor5;
    int avgRSSIcolor5;

    //statistiche colore 6
    int bestRSSIcolor6;
    int worstRSSIcolor6;
    int avgRSSIcolor6;
    
    struct statistica_link* next;
	
	sem_t mutex;
};

#endif

