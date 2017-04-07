CC	?= gcc
CFLAGS	?= -g -pipe -fPIC
LDFLAGS ?= -ldl -lm -ljabber
PKG_CONFIG  ?= pkg-config

DIR_PERM	= 0755
FILE_PERM	= 0644

HEADERS=-I./headers/jabber

CFLAGS	+= $(shell $(PKG_CONFIG) --cflags glib-2.0 gio-2.0 purple) $(shell xml2-config --cflags) $(HEADERS)
LIBS	+= $(shell $(PKG_CONFIG) --libs glib-2.0 gio-2.0 purple)  $(shell xml2-config --libs) -L$(shell pkg-config --variable=plugindir purple)
PLUGIN_DIR_PURPLE	=  $(shell $(PKG_CONFIG) --variable=plugindir purple)
DATA_ROOT_DIR_PURPLE	=  $(shell $(PKG_CONFIG) --variable=datarootdir purple)

PRPL_NAME	= jabber_http_file_upload.so
PRPL_LIBNAME	= ${PRPL_NAME}

SKYPEWEB_SOURCES = \
	src/hfu_disco.c \
	src/hfu_util.c \
	src/jabber_http_file_upload.c


.PHONY:	all clean install
all: $(PRPL_NAME)
install:
	mkdir -m $(DIR_PERM) -p $(DESTDIR)$(PLUGIN_DIR_PURPLE)
	install -m $(FILE_PERM) $(PRPL_LIBNAME) $(DESTDIR)$(PLUGIN_DIR_PURPLE)/$(PRPL_NAME)

clean:
	rm -f jabber_http_file_upload.so

$(PRPL_NAME): $(SKYPEWEB_SOURCES)
	$(CC)  -Wall -I. $(CFLAGS) $(SKYPEWEB_SOURCES) -o $@ $(CFLAGS) $(LIBS) $(LDFLAGS) -shared
