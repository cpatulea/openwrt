ARCH:=mips
SUBTARGET:=falcon
BOARDNAME:=Falcon
FEATURES:=squashfs
DEVICE_TYPE:=other
CFLAGS+= -mtune=mips32r2

DEFAULT_PACKAGES+= kmod-ifxos gpon-base-files kmod-leds-gpio kmod-ledtrig-heartbeat \
	kmod-gpon-optic-drv gpon-optic-drv kmod-gpon-onu-drv gpon-onu-drv \
	gpon-pe-firmware gpon-omci-api gpon-omci-onu gpon-luci

define Target/Description
	Lantiq Falcon
endef
