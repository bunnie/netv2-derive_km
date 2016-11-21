
CC=gcc

CFLAGS=-Wall -g

derive_km: derive_km.c compute_ksv.c
	gcc -o derive_km $(CFLAGS) derive_km.c compute_ksv.c

clean:
	-rm -f *.o *~ core derive_km

