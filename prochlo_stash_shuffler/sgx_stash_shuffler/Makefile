CXXFLAGS = -MD -Wall -std=c++11 -I.
LDFLAGS = -lcrypto -lssl 
SHUFFLER_LIB = libstash_shuffler.a
LIBS = $(SHUFFLER_LIB)
APPS = stash_shuffle stash_clean_up stash_distribute
AR = ar
RANLIB = ranlib

CXXFLAGS += $(App_Cpp_Flags)
LDFLAGS += $(App_Link_Flags)
SHUFFLER_OBJS = untrusted/stash_shuffler_u.o

Enclave_Cpp_Files :=  Enclave.cc shuffle_data.cc shuffle_crypter.cc \
	 	      stash_shuffler.cc stash_window.cc stash_stash.cc \
		      append_only_allocator.cc

all: $(APPS) enclave

clean: sgx_clean
	rm -f $(SHUFFLER_LIB) $(SHUFFLER_OBJS) $(APPS)  untrusted/*.o *.d untrusted/*.d

untrusted/%.o: untrusted/%.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

untrusted/stash_shuffle.o: untrusted/Enclave_u.o

stash_shuffle: untrusted/stash_shuffle.o untrusted/Enclave_u.o
	$(CXX) $(CXXFLAGS)  untrusted/stash_shuffle.o untrusted/Enclave_u.o  -o $@ $(LDFLAGS)

stash_clean_up: untrusted/stash_clean_up.o untrusted/Enclave_u.o
	$(CXX) $(CXXFLAGS)  untrusted/stash_clean_up.o untrusted/Enclave_u.o  -o $@ $(LDFLAGS)

stash_distribute: untrusted/stash_distribute.o untrusted/Enclave_u.o
	$(CXX) $(CXXFLAGS)  untrusted/stash_distribute.o untrusted/Enclave_u.o  -o $@ $(LDFLAGS)

include ../third_party/intel/sgxsdk/Makefile.inc
-include *.d untrusted/*.d
