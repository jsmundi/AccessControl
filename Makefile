CFLAGS=-g -std=c99 -pedantic -Wall

all: get 

get: get.o
	gcc get.o -o get
	chmod u+s get

get.o: get.c
	gcc -c $(CFLAGS) get.c

clean:
	rm -f get get.o 
