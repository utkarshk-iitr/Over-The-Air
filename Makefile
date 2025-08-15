CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -I.
LDFLAGS ?= -loqs -lcrypto -lpthread

all: server_pq client_pq

server_pq: server_pq.cpp pqcrypto.h
	$(CXX) $(CXXFLAGS) -o $@ server_pq.cpp $(LDFLAGS)

client_pq: client_pq.cpp pqcrypto.h
	$(CXX) $(CXXFLAGS) -o $@ client_pq.cpp $(LDFLAGS)

clean:
	rm -f server_pq client_pq
