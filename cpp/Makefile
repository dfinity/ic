CXXFLAGS = -Wall -O2 --std=c++17

all: infogetty prestorecon

infogetty: LDFLAGS += -lsystemd
infogetty: infogetty-cpp/infogetty.o infogetty-cpp/network_info.o
	$(CXX) -o $@ $^ $(LDFLAGS)

prestorecon: LDFLAGS += -lselinux -pthread
prestorecon: prestorecon-cpp/prestorecon.o
	$(CXX) -o $@ $^ $(LDFLAGS)
