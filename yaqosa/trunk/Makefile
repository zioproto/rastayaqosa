#KERNEL_HEADERS=-I/usr/src/linux/include

CC=gcc
#CC=mipsel-uclibc-gcc


CFLAGS= -Wall -g -O2 $(INCLUDE)                                                           
LDFLAGS=                                                                        
INCLUDE= -Iinclude/ $(KERNEL_HEADERS)                                        
#LIBS= -L/usr/lib/libbridge.a -lpthread -lbridge -lm   

LOADLIBES= $(LIBS)

OBJS= distributore.o readconf.o decisore.o rules.o

#CFLAGS= -g -D_PC_ $(INCLUDE) -Wall

VPATH= src/

EXEC= distributore

default: all

all: $(OBJS) $(EXEC)

$(EXEC): $(OBJS)

clean:
	-rm -f $(OBJS)
	-rm -f $(EXEC)

rebuild: clean all

strip:
	strip $(EXEC)