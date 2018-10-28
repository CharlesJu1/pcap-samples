CC=gcc
OBJ_DIR=obj
LIBS=-lpcap

_DEPS = hellomake.h
DEPS = $(patsubst %, src/%, $(_DEPS))

_OBJ = testpcap1.o
OBJ = $(patsubst %, $(OBJ_DIR)/%, $(_OBJ))

$(info OBJ = "$(OBJ)")

$(OBJ_DIR)/%.o: %.c
	@mkdir -p obj
	$(CC) -c -o $@ $< $(CFLAGS)

testpcap1: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -rf $(OBJ_DIR)
