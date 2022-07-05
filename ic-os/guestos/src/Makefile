CXXFLAGS = -Wall -O2 --std=c++17
LDFLAGS = -lsystemd

infogetty: infogetty.o network_info.o
	$(CXX) -o $@ $^ $(LDFLAGS)
