LIBS = -lprochlo -lcrypto
OBJS = generator.o

all: generator

generator: $(OBJS) $(LIBPROCHLO)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f generator $(OBJS) *.d

-include *.d
