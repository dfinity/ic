CXXFLAGS = -Wall -O2 --std=c++17

all: infogetty

infogetty: LDFLAGS += -lsystemd
infogetty: infogetty-cpp/infogetty.o infogetty-cpp/network_info.o
	$(CXX) -o $@ $^ $(LDFLAGS)
