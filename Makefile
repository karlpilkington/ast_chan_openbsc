ASTSRC?=../asterisk
OPENBSCSRC?=../openbsc


OPENBSC_SRC = bsc_init.c vty_interface.c vty_interface_layer3.c
OPENBSC_LIBS = libmsc.a libbsc.a libmsc.a libvty.a
OPENBSC_INCLUDES = -I$(OPENBSCSRC)/include
OPENBSC_LDFLAGS = -ldl -ldbi -lcrypt


ASTTOPDIR=$(ASTSRC)

# Asterisk configure options
ifneq ($(wildcard $(ASTSRC)/makeopts),)
  include $(ASTSRC)/makeopts
endif

# Need to replicate some of the Asterisk top makefile logic
	# CFLAGS
_ASTCFLAGS:=-I$(ASTTOPDIR)/include $(CONFIG_CFLAGS) $(COPTS)
_ASTLDFLAGS:=$(CONFIG_LDFLAGS) $(LDOPTS)

	# Link of shared objects
ifneq ($(findstring darwin,$(OSARCH)),)
  _ASTCFLAGS+=-D__Darwin__
  SOLINK=-dynamic -bundle -Xlinker -macosx_version_min -Xlinker 10.4 -Xlinker -undefined -Xlinker dynamic_lookup -force_flat_namespace
else
# These are used for all but Darwin
  SOLINK=-shared
  ifneq ($(findstring BSD,$(OSARCH)),)
    _ASTLDFLAGS+=-L/usr/local/lib
  endif
endif

ifeq ($(OSARCH),SunOS)
  SOLINK=-shared -fpic -L/usr/local/ssl/lib -lrt
endif

ifeq ($(OSARCH),OpenBSD)
  SOLINK=-shared -fpic
endif

# Menuselect stuff
-include $(ASTTOPDIR)/menuselect.makeopts $(ASTTOPDIR)/menuselect.makedeps

# Modules rules
MODULE_PREFIX=chan
MENUSELECT_CATEGORY=CHANNELS
MENUSELECT_DESCRIPTION=Channel Drivers

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

# Add OpenBSC stuff in the mix
chan_openbsc.o:: _ASTCFLAGS+=$(OPENBSC_INCLUDES)
chan_openbsc.so: $(addprefix $(OPENBSCSRC)/src/,$(patsubst %.c,%.o,$(OPENBSC_SRC))) $(addprefix $(OPENBSCSRC)/src/,$(OPENBSC_LIBS))
chan_openbsc.so:: _ASTLDFLAGS+=$(OPENBSC_LDFLAGS)

