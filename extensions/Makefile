CC ?= gcc
CONTRIB_SO :=

all: $(CONTRIB_SO)

$(CONTRIB_SO): %.so: %.c
	$(CC) -O2 -g -fPIC -shared -Wl,-T,../makedumpfile.ld -o $@ $^

clean:
	rm -f $(CONTRIB_SO)

