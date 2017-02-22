DESTDIR=/usr/local

CFLAGS += -O2 -Wall -Werror -pedantic -std=gnu99

sigma_tcp: i2c.c regmap.c

install:
	install -d $(DESTDIR)/usr/sbin
	install sigma_tcp $(DESTDIR)/usr/sbin

clean:
	rm -rf sigma_tcp *.o
