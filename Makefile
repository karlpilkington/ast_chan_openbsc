ASTSRC?=../asterisk

-include $(ASTSRC)/menuselect.makeopts $(ASTSRC)/menuselect.makedeps

LOADABLE_MODS=chan_openbsc

ASTTOPDIR=$(ASTSRC)
INCLUDE=-I$(ASTSRC)/include -I/usr/local/include

ifneq ($(wildcard $(ASTSRC)/makeopts),)
  include $(ASTSRC)/makeopts
endif

ifeq ($(OSARCH),SunOS)
  ASTLIBDIR=/opt/asterisk/lib
else
  ASTLIBDIR=$(libdir)/asterisk
endif
MODULES_DIR=$(ASTLIBDIR)/modules

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

%.so: %.o
	$(CC) -shared -o $@ $<

%.o: %.c
	$(CC) -fPIC $(INCLUDE) -DAST_MODULE=\"$*\" -o $@ -c $<

