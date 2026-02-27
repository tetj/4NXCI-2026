include config.mk

.PHONY: clean

SRCDIR = src
INCDIR = include
INCLUDE = -I $(INCDIR) -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE) lib
	$(MAKE) 4nxci

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

4nxci: $(SRCDIR)/sha.o $(SRCDIR)/aes.o $(SRCDIR)/extkeys.o $(SRCDIR)/pki.o $(SRCDIR)/hfs0.o $(SRCDIR)/utils.o $(SRCDIR)/nsp.o $(SRCDIR)/nca.o $(SRCDIR)/cnmt.o $(SRCDIR)/xci.o $(SRCDIR)/main.o $(SRCDIR)/filepath.o $(SRCDIR)/ConvertUTF.o $(SRCDIR)/romfs.o $(SRCDIR)/threadpool.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

$(SRCDIR)/aes.o: $(INCDIR)/aes.h $(INCDIR)/types.h

$(SRCDIR)/extkeys.o: $(INCDIR)/extkeys.h $(INCDIR)/types.h $(INCDIR)/settings.h

$(SRCDIR)/filepath.o: $(SRCDIR)/filepath.c $(INCDIR)/types.h

$(SRCDIR)/hfs0.o: $(INCDIR)/hfs0.h $(INCDIR)/types.h

$(SRCDIR)/main.o: $(SRCDIR)/main.c $(INCDIR)/pki.h $(INCDIR)/types.h $(INCDIR)/version.h

$(SRCDIR)/pki.o: $(INCDIR)/pki.h $(INCDIR)/aes.h $(INCDIR)/types.h

nsp.o: nsp.h

cnmt.o: cnmt.h

nca.o: nca.h aes.h sha.h bktr.h filepath.h types.h pfs0.h npdm.h

sha.o: sha.h types.h

utils.o: utils.h types.h

xci.o: xci.h types.h hfs0.h

romfs.o: romfs.h nacp.h

ConvertUTF.o: ConvertUTF.h

clean:
	rm -f *.o 4nxci 4nxci.exe

clean_full:
	rm -f *.o 4nxci 4nxci.exe
	cd mbedtls && $(MAKE) clean

dist: clean_full
	$(eval NXCIVER = $(shell grep '\bNXCI_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir 4nxci-$(NXCIVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls 4nxci-$(NXCIVER)
	tar czf 4nxci-$(NXCIVER).tar.gz 4nxci-$(NXCIVER)
	rm -r 4nxci-$(NXCIVER)

