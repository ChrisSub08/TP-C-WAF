CC = gcc
CFLAGS = -Wall -O2 -fPIC -pthread
LDFLAGS = 
SRC_WAF = waf.c
SRC_MAIN = main.c
LIBNAME = lib$(SRC_WAF:.c=.so)
LIB = $(SRC_WAF:.c=)
OBJ_WAF = $(SRC_WAF:.c=.o)
OBJ_MAIN = $(SRC_MAIN:.c=.o)
TARGET = $(SRC_MAIN:.c=)

all: $(LIBNAME) $(TARGET)

$(LIBNAME): $(OBJ_WAF)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TARGET): $(OBJ_MAIN) $(LIBNAME)
	$(CC) -o $@ $(OBJ_MAIN) -L. -l$(LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_WAF) $(OBJ_MAIN) $(TARGET) $(LIBNAME)

run: all
	@export LD_LIBRARY_PATH=. && ./$(TARGET)

.PHONY: all clean run
