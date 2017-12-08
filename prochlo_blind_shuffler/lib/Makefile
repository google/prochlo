OBJS = prochlo.o crypto.o

all: libprochlo.a

libprochlo.a: $(OBJS)
	ar cru $(@) $(OBJS)
	ranlib $(@)

clean:
	rm -f $(GEN) libprochlo.a *.o *.d

-include *.d
