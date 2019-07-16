CC = cc
INC = -I ./
LIB = -L ./ -lpcap

CFLAGS = -W -Wall -O2
#CFLAGS = -g -fstack-protector

OBJS = main.o 

TARGET = packetCuter

all:$(TARGET)
.c.o:
	$(CC) -c $(CFLAGS) $< $(INC)
$(TARGET):$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(INC) $(LIBS)


clean:
	$(RM) $(TARGET)
	$(RM) *.o
