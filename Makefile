#---------------------------------------------------------------------
# Applied Expert Systems, Inc.
# Copyright 2009
#
# Project: CleverView TCP/IP on LinuxZ
# 
# This makefile builds the monitor daemon(s) and related unit-test apps
#
#---------------------------------------------------------------------
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

CC=gcc

OBJS1=cv4rtdaemon.o dbaseinterface.o dthelpers.o 
OBJS2=dthelpers.o
OBJS3=sslwrapper.o
OBJS4=tcpclient.o
OBJS5=portmon.o
OBJS6=testdocker.o

TARGETS=tcpclient cv4monwrapper cv4portmon  cv4rtdaemon

CFLAGS=-I. `net-snmp-config --cflags` `mysql_config --cflags` 
DAEMON_CFLAGS=-I. `net-snmp-config --cflags` `mysql_config --cflags` 
BUILDLIBS=`net-snmp-config --libs` `mysql_config --libs` 
DAEMON_BUILDLIBS=`net-snmp-config --libs` `mysql_config --libs` 
BUILDAGENTLIBS=`net-snmp-config --agent-libs`
# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

cv4rtdaemon: $(OBJS1)
#	$(CC) -g -m64 -Wall -o cv4rtdaemon $(OBJS1) $(DAEMON_CFLAGS) $(DAEMON_BUILDLIBS)  
	$(CC) -g -Wall -m64 -lssl -o cv4rtdaemon $(OBJS1) $(DAEMON_CFLAGS) $(DAEMON_BUILDLIBS) -lm || exit

tcpclient: $(OBJS4)
	$(CC) -g -Wall -m64 -lssl -o tcpclient $(OBJS4) $(BUILDAGENTLIBS)

testdocker: $(OBJS6)
	$(CC) -g -Wall -m64 -lssl -o testdocker $(OBJS6) $(BUILDAGENTLIBS)

cv4monwrapper: $(OBJS3)
	$(CC) -g -m64 -Wall -lssl -o cv4monwrapper $(OBJS3)

cv4portmon: 
	$(CC) -g -m64 -Wall -lssl portmon.c -o cv4portmon

clean:
	rm $(OBJS1) $(OBJS4) $(OBJS3) $(TARGETS)

