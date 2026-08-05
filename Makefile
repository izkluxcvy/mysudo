TARGET := mysudo

CC := clang
CFLAGS := -std=c23 -Wall -Wextra
LDFLAGS := -lcrypt

SRC := mysudo.c

.PHONY: all post clean

all: $(TARGET) post

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

post:
	sudo chown root:root $(TARGET)
	sudo chmod u+s $(TARGET)

clean:
	rm -f $(TARGET)
