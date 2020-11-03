PROJECT_NAME := "RSA implementation"
EXEC_NAME := rsa_mat
MAINTAINER_NAME := Lailouezzz
MAINTAINER_MAIL := alanlebouder@gmail.com
MAINTAINER := $(MAINTAINER_NAME) <$(MAINTAINER_MAIL)>
VERSION_MAJOR := 0
VERSION_MINOR := 0
VERSION_PATCH := 0
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

# Project directories

BUILD_DIR := ./build
INCDIR := ./include
SRCDIR := ./src

# Project files

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(SRCS:$(SRCDIR)/%.c=$(BUILD_DIR)/%.o)
DEP := $(OBJS:%.o=%.d)

# Buildtool variable

CC := gcc
CWERROR := all extra write-strings fatal-errors pedantic
CWARN := $(CWERROR:%=-W%)
PPDEFINE := -DVERSION="$(VERSION)" -DMAINTAINER="$(MAINTAINER_NAME)"
CFLAGS := -I $(INCDIR) $(CWARN) $(PPDEFINE) -g -std=gnu17 -pedantic
LD := gcc
LDFLAGS := -lgmp

# PHONY targets

.PHONY: all clean re getmaintainer getversion

# General targets

all: $(EXEC_NAME)

clean:
	@echo "Removing the build folder"
	@rm -rf $(BUILD_DIR)
	@rm -f $(EXEC_NAME)

re: clean all

# Some informations

getmaintainer:
	@echo $(MAINTAINER)

getversion:
	@echo $(VERSION)

# Project target

$(EXEC_NAME): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

# Build rules

$(BUILD_DIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -o $@ -c $<

-include $(DEP)
