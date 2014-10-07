WIN32 := 1

MINGW_HOME := C:/mingw

MSYS_HOME := $(MINGW_HOME)/msys/1.0

WINPCAP_HOME := D:/PrivateFolders/Elad/WpdPack

export PATH := $(MINGW_HOME)/bin;$(MSYS_HOME)/bin:$(PATH)

BIN_EXT := .exe

LIB_PREFIX := 

LIB_EXT := .lib

G++ := g++.exe

AR := ar.exe

RM := rm.exe

CP := cp.exe