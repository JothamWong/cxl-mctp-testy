CC = gcc
TARGET = test
SOURCE = cxl-mctp-testy.c
OBJECT = cxl-mctp-testy.o

.PHONY: all
all: $(TARGET)
$(TARGET): $(OBJECT)
	$(CC) $(OBJECT) -o $(TARGET)

%.o: %.c
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJECT) $(TARGET)