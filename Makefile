# Compiler
CC = clang

# Compiler flags
CFLAGS = -std=c11 -Wall -Wextra -Werror

# Debugging flags
DEBUG_FLAGS = -std=c11 -Wall -Wextra -Werror -g

# Detect platform
UNAME_S := $(shell uname -s)

# Include directories and library directories for macOS
ifeq ($(UNAME_S), Darwin)
    INCLUDES = \
        -Iinclude \
        -I/opt/homebrew/Cellar/libmagic/5.45/include \
        -I/opt/homebrew/Cellar/jansson/2.14/include \
        -I/opt/homebrew/Cellar/libuv/1.48.0/include \
        -I/opt/homebrew/Cellar/duckdb/1.0.0/include \
        -I/opt/homebrew/Cellar/zlog/1.2.18/include \
        -I/opt/homebrew/opt/openssl/include

    LDFLAGS = \
        -L/opt/homebrew/Cellar/libmagic/5.45/lib \
        -L/opt/homebrew/Cellar/jansson/2.14/lib \
        -L/opt/homebrew/Cellar/libuv/1.48.0/lib \
        -L/opt/homebrew/Cellar/duckdb/1.0.0/lib \
        -L/opt/homebrew/Cellar/zlog/1.2.18/lib \
        -L/opt/homebrew/opt/openssl/lib
endif

# Include directories and library directories for Linux
ifeq ($(UNAME_S), Linux)
    INCLUDES = \
        -Iinclude \
        -I/usr/include \
        -I/usr/local/include

    LDFLAGS = \
        -L/usr/lib \
        -L/usr/local/lib

    # Specific includes and libs for Linux if needed
    INCLUDES += \
        -I/usr/include/libmagic \
        -I/usr/include/jansson \
        -I/usr/include/libuv \
        -I/usr/include/duckdb \
        -I/usr/include/zlog \
        -I/usr/include/openssl

    LDFLAGS += \
        -L/usr/lib/x86_64-linux-gnu \
        -L/usr/local/lib
endif

# Libraries to link against
LIBS = \
    -lmagic \
    -ljansson \
    -luv \
    -lduckdb \
    -lzlog \
    -lssl \
    -lcrypto

# Source files
SRCS = main.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable names
EXEC = fsnode
DEBUG_EXEC = fsnode_dbg
UBUNTU_EXEC = fsnode_l

# Default target
all: $(EXEC)

# Link the executable
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

# Compile the source files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Debug target
debug: CFLAGS = $(DEBUG_FLAGS)
debug: $(DEBUG_EXEC)

# Link the debug executable
$(DEBUG_EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

# Cross-compile for Ubuntu
ubuntu: CFLAGS += -target x86_64-linux-gnu
ubuntu: LDFLAGS += --sysroot /usr/x86_64-linux-gnu
ubuntu: $(UBUNTU_EXEC)

# Link the Ubuntu executable
$(UBUNTU_EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

# Clean up
clean:
	rm -f $(OBJS) $(EXEC) $(DEBUG_EXEC) $(UBUNTU_EXEC)

.PHONY: all clean debug ubuntu
