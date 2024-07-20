include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=flowdumper
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/flowdumper
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Measurement tool that dumps and uploads network flow information
	DEPENDS:=+libnetfilter-conntrack +libmnl +libnfnetlink +libstdcpp +curl
endef

# Package description; a more verbose description on what our package does
define Package/flowdumper/description
	flowdumper is a measurement tool that runs in the background,
	obtains information about network flows from the kernel, and dumps it
	into a temporary file. It is bundled with a script that uploads
	the dump file to a remote endpoint every night for research purposes.
endef

TARGET_CXXFLAGS += --std=c++23

# Package preparation instructions; create the build directory and copy the source code.
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
		mkdir -p $(PKG_BUILD_DIR)
		cp ./src/* $(PKG_BUILD_DIR)
		$(Build/Patch)
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/flowdumper/install
		$(INSTALL_DIR) $(1)/etc/init.d
		$(INSTALL_BIN) ./files/flowdumper.init $(1)/etc/init.d/flowdumper
		$(INSTALL_DIR) $(1)/etc/uci-defaults
		$(INSTALL_BIN) ./files/99_flowdumper.uci-defaults $(1)/etc/uci-defaults/99_flowdumper
		$(INSTALL_DIR) $(1)/usr/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/flowdumper $(1)/usr/bin/
		$(INSTALL_BIN) ./files/flowdumper_upload.sh $(1)/usr/bin/
		$(INSTALL_DIR) $(1)/etc/sysctl.d
		$(INSTALL_CONF) ./files/flowdumper.sysctl $(1)/etc/sysctl.d/42-flowdumper.conf
		$(INSTALL_DIR) $(1)/etc/config
		$(INSTALL_CONF) ./files/flowdumper.config $(1)/etc/config/flowdumper
endef

define Package/flowdumper/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	rm -f /etc/flowdumper_id
	sed -i '\|flowdumper_upload|d' /etc/crontabs/root
fi
exit 0
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,flowdumper))
