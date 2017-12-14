LIBS = -lprochlo -lcrypto
OBJS = test.o

all: test

test: $(OBJS) $(LIBPROCHLO)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f test $(OBJS) *.d

-include *.d
