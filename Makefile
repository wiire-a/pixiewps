include $(TOPDIR)/rules.mk

PKG_NAME:=pixiewps
PKG_RELEASE:=1.1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/pixiewps
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=wireless
	TITLE:=An offline WPS Bruteforce utility
	DEPENDS:=+libopenssl
	URL:=https://github.com/wiire/pixiewps
endef

define Package/pixiewps/description
	An offline WPS Bruteforce utility
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/pixiewps/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pixiewps $(1)/usr/bin/
endef

$(eval $(call BuildPackage,pixiewps))
