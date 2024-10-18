ALLCPP=$(wildcard *.cpp)
SOURCES=$(filter-out authlib.cpp,$(ALLCPP))
TARGETS=$(patsubst %.cpp,%,$(SOURCES))
CPPFLAGS=-Wall -pedantic -Wextra -std=c++11 -Wno-deprecated-declarations -DDOMAIN=\"api.authservice.co.uk\" #-g -DDEBUG
LDFLAGS=-lcrypto -lssl 
#DOMAIN=api.authservice.co.uk
C=g++

all: $(TARGETS)

authlib.o: authlib.cpp
	$C $(CPPFLAGS) -c authlib.cpp

%: %.cpp authlib.o
	$C $(CPPFLAGS) $< authlib.o -lcrypto -o $@

clean:
	rm -f $(TARGETS)
	rm -f *~ *.o a.out

# run: all
#	$(foreach target, $(TARGETS), DOMAIN=$(DOMAIN) ./$(target);)

#A Makefile. This file compiles both your secure and your subverted login procedures.