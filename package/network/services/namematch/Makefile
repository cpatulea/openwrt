include $(TOPDIR)/rules.mk

PKG_NAME:=namematch
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/namematch
	TITLE:=namematch
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	DEPENDS:=+libnfnetlink +libmnl +libnetfilter-queue
endef

define Package/namematch/description
namematch is a userland NFQUEUE helper for just-in-time DNS resolution of a
hostname whitelist.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/namematch/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/namematch $(1)/sbin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/namematch.config $(1)/etc/config/namematch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/namematch.init $(1)/etc/init.d/namematch
endef

$(eval $(call BuildPackage,namematch))
