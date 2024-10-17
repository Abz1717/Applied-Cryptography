ALLCPP=$(wildcard *.cpp)
SOURCES=$(filter-out authlib.cpp,$(ALLCPP))
TARGETS=$(patsubst %.cpp,%,$(SOURCES))
CPPFLAGS=-Wall -pedantic -Wextra -std=c++11 -Wno-deprecated-declarations
LDFLAGS=-lcrypto -lssl  
C=g++
export DOMAIN=api.authservice.co.uk

all: $(TARGETS)

authlib.o: authlib.cpp
	$C $(CPPFLAGS) -c authlib.cpp

%: %.cpp authlib.o
	$C $(CPPFLAGS) $< authlib.o -lcrypto -o $@

clean:
	rm -f $(TARGETS)
	rm -f *~ *.o a.out

#A Makefile. This file compiles both your secure and your subverted login procedures.