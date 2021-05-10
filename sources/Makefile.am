
include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_udptun

mod_LTLIBRARIES = mod_udptun.la
mod_udptun_la_SOURCES  = mod_udptun.c cipher.c
mod_udptun_la_CFLAGS   = $(AM_CFLAGS) -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-label -Wno-declaration-after-statement -I.
mod_udptun_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_udptun_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

$(am_mod_udptun_la_OBJECTS): mod_udptun.h cipher.h
