TARGET = img4tool_tool
INSTALLTARGET = img4tool
CFLAGS += -Wall -std=c11
LDFLAGS += -lcrypto -lplist
SRC_DIR += img4tool
OBJECTS += $(SRC_DIR)/img4tool.o $(SRC_DIR)/img4.o 

all : $(TARGET)

$(TARGET) : $(OBJECTS)
		$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $(TARGET)
		@echo "Successfully built $(TARGET)"

$(SRC_DIR)/%.o : $(SRC_DIR)/%.c
		$(CC) $(CFLAGS)  $< -c -o $@

install : $(TARGET)
		cp $(TARGET) /usr/local/bin/$(INSTALLTARGET)
		@echo "Installed $(INSTALLTARGET)"
clean :
		rm -rf img4tool/*.o $(TARGET)
