# Makefile
TARGET=rsa
PREFIX?=/usr/local
INSTBINDIR=bin
INSTMANDIR=share/man
MANPAGENUMBER=1

ODIR=obj
SDIR=src
IDIR=include
OUTDIR=bin

INCLUDES=$(wildcard $(IDIR)/*.h)

LIBS=m
CC=gcc
CFLAGS=-Og -g -Wall -Wunreachable-code -pedantic -I$(IDIR) -l$(LIBS)

_OBJS=util.o rsa.o
OBJS=$(patsubst %,$(ODIR)/%,$(_OBJS))

$(ODIR)/%.o: $(SDIR)/%.c $(INCLUDES)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(OUTDIR)/$@ $(SDIR)/main.c $(OBJS)
