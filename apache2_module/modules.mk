mod_apache2_module.la: mod_apache2_module.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_apache2_module.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_apache2_module.la
