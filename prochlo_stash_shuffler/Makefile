TOP := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

export CXXFLAGS += -MD -Wall -g -std=c++11 -I$(TOP) 
export LDFLAGS += -L$(TOP)/lib  -L/usr/local/lib
export LIBPROCHLO = $(TOP)/lib/libprochlo.a

SUBDIRS = lib \
	  generator \
	  sgx_stash_shuffler \
	  etc

SUBCLEAN = $(addsuffix .clean,$(SUBDIRS))

.PHONY: all clean $(SUBDIRS) $(SUBCLEAN) test
all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean: $(SUBCLEAN)

$(SUBCLEAN): %.clean:
	$(MAKE) -C $* clean

