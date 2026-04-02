CC       ?= gcc
CFLAGS    = -Wall -Wextra -O2 -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS   = -lpthread
BIN       = armscan

SRCS = main.c threadpool.c output.c target.c util.c \
       protocols/ssh.c protocols/mysql.c protocols/pgsql.c protocols/redis.c \
       crypto/sha256.c crypto/sha1.c crypto/md5.c \
       crypto/aes128.c crypto/bignum.c crypto/pbkdf2.c

OBJS = $(SRCS:.c=.o)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BIN) $(OBJS)

static: LDFLAGS += -static
static: all

.PHONY: all clean static
