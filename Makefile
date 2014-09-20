# Makefile for ftpd
CC:=gcc
OPTIONS:=-O3 -Wall -g -lpthread
SUBOPTS:=-Wall -c -o
OBJECTS:=dxyh_lib.o ftpd.o ftpd_main.o error.o record.o dxyh_thread_lib.o
SOURCES:=dxyh_lib.c ftpd.c ftpd_main.c error.c record.c dxyh_thread_lib.c 
HEADERS:=dxyh.h dxyh_thread.h ftpd.h error.h record.h

ftpd_main: $(OBJECTS)
	$(CC) $(OPTIONS) $^ -o $@
ftpd_main.o: ftpd_main.c record.h ftpd.h dxyh_thread.h
	$(CC) ftpd_main.c $(SUBOPTS) $@
error.o: error.c error.h dxyh_thread.h
	$(CC) error.c $(SUBOPTS) $@
record.o: record.c record.h error.h dxyh.h dxyh_thread.h
	$(CC) record.c $(SUBOPTS) $@
dxyh_lib.o: dxyh_lib.c dxyh.h error.h
	$(CC) dxyh_lib.c $(SUBOPTS) $@
dxyh_thread_lib.o: dxyh_thread_lib.c dxyh_thread.h error.h dxyh_thread.h
	$(CC) dxyh_thread_lib.c $(SUBOPTS) $@
ftpd.o: ftpd.c error.h record.h ftpd.h dxyh.h
	$(CC) ftpd.c $(SUBOPTS) $@

.PHONY: clean
clean:
	rm -f *.o *.txt ftpd_main
