CC      := gcc
CFLAGS  := -ggdb -Wall -lssl -lcrypto
RM      := rm -f

sources := main.c
targets := main

all: $(targets)