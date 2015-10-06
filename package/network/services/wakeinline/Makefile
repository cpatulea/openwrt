include $(TOPDIR)/rules.mk

PKG_NAME:=wakeinline
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/wakeinline
	TITLE:=wakeinline
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	DEPENDS:=+libnfnetlink +libmnl +libnetfilter-queue
endef

define Package/wakeinline/description
wakeinline is a userland NFQUEUE helper for sending Wake-on-LAN magic packets.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/wakeinline/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wakeinline $(1)/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wakeinline.init $(1)/etc/init.d/wakeinline
endef

$(eval $(call BuildPackage,wakeinline))
