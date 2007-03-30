CC=gcc
#CC=mipsel-uclibc-gcc


#CFLAGS= -Wall -g -O2 $(INCLUDE)                                                           
LDFLAGS=                                                                        
#INCLUDE= -Iinclude/ -Ilibbridge/ $(KERNEL_HEADERS)                                        
INCLUDE= -Iinclude/ $(KERNEL_HEADERS)

#LIBS= -L/opt/brcm/hndtools-mipsel-uclibc/lib/libbridge.a -lpthread -lm  -lbridge
LIBS= -lpthread -lm

LOADLIBES= $(LIBS)

OBJS= rasta.o subs.o statistica.o comandi.o readconf.o

CFLAGS= -g -D_PC_ $(INCLUDE) -Wall

VPATH= src/

EXEC= rasta

#default: libbridge all
default: all

all: $(OBJS) $(EXEC)

$(EXEC): $(OBJS)

clean:
	-rm -f $(OBJS)
	-rm -f $(EXEC)
	

rebuild: clean all

