CXX := g++
OUTPUT := traceio
CXXFLAGS := -std=c++11
SRCS := \
	main.cpp \
	flag_maps.cpp
OBJS := $(SRCS:.cpp=.o)

all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(OUTPUT)

clean:
	rm -f $(OUTPUT) $(OBJS)
