include $(TOPDIR)/rules.mk

PKG_NAME:=wireshark
PKG_VERSION:=1.2.10
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://www.wireshark.org/download/src/all-versions/
PKG_MD5SUM:=f8bc926956c13fcddb4df0601011ceef
PKG_CAT:=bzcat

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/pcap

include $(INCLUDE_DIR)/nls.mk

define Package/wireshark/Default
	URL:=http://wireshark.org/
endef

define Package/wireshark
$(call Package/wireshark/Default)
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpcap +glib2
	TITLE:=Network capture utility
endef

CONFIGURE_ARGS += \
	--prefix=$(STAGING_DIR)/usr \
	--includedir=$(STAGING_DIR)/usr/include \
	--oldincludedir=$(STAGING_DIR)/usr/include \
	--with-pcap=$(STAGING_DIR)/usr/lib \
	--disable-usr-local \
	--enable-wireshark=no \
	--disable-gtktest \
	--disable-tshark \
	--disable-capinfos \
	--disable-editcap \
	--disable-mergecap \
	--disable-text2pcap \
	--disable-idl2wrs \
	--disable-randpkt \
	--disable-dftest \
	--disable-rawshark \
	--without-zlib \
	--without-pcre \
	--without-krb5 \
	--without-lua \
	--without-plugins \
	--without-libsmi \
	--without-gnutls \
	--without-gcrypt \
	--without-portaudio

define Build/Compile
	touch $(PKG_BUILD_DIR)/svnversion.h
	$(MAKE) -C $(PKG_BUILD_DIR)/wsutil
	$(MAKE) -C $(PKG_BUILD_DIR)/wiretap
	$(MAKE) -C $(PKG_BUILD_DIR) dumpcap
endef

define Package/wireshark/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/.libs/dumpcap $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/wsutil/.libs/libwsutil.so* $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/wiretap/.libs/libwiretap.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,wireshark))
