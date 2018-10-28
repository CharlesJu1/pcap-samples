CC=gcc
OBJ_DIR=obj
LIBS=-lpcap

_DEPS = hellomake.h
DEPS = $(patsubst %, src/%, $(_DEPS))

_OBJ = ldev.o
OBJ = $(patsubst %, $(OBJ_DIR)/%, $(_OBJ))

$(info OBJ = "$(OBJ)")

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p obj
	$(CC) -c -o $@ $< $(CFLAGS)

ldev: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -rf $(OBJ_DIR)
