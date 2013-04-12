CC     = gcc
LINKER = gcc
CFLAGS = -g
LDFLAGS = -c 
OUTPUT = tracer


all:	main sample trace
	$(LINKER) trace.o main.o -o $(OUTPUT)
     
trace: trace.c 
	$(CC) $(LDFLAGS) $(CFLAGS) trace.c

main: main.c
	$(CC) $(LDFLAGS) $(CFLAGS) main.c

sample: sample.c
	$(CC) $(CFLAGS) sample.c -o sample
	
	
clean: 
	rm *.o $(OUTPUT) sample
