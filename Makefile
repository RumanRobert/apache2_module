##
##  Makefile -- Build procedure for sample apache2_module Apache module
##  Autogenerated via ``apxs -n apache2_module -g''.
##

builddir=.
top_srcdir=/usr/share/apache2
top_builddir=/usr/share/apache2
include /usr/share/apache2/build/special.mk
LDFLAGS += -L/usr/lib/x86_64-linux-gnu
LDFLAGS += -lapr-1
CFLAGS += -l/usr/include/apr-1.0
#   the used tools
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_apache2_module.o mod_apache2_module.lo mod_apache2_module.slo mod_apache2_module.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/apache2_module

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
