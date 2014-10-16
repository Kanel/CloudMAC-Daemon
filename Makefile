wtp:
	export BASE="/home/ori/cloudmac/attitude" &&\
	export KLIB="$$BASE/build_dir/linux-ixp4xx_generic/linux-3.3.8/" &&\
	export KLIB_BUILD="$$KLIBV" &&\
	export BIN="$$BASE/staging_dir/toolchain-armeb_v5te_gcc-4.6-linaro_uClibc-0.9.33.2/bin/" &&\
	export PATH="$$PATH:$$BIN" &&\
	export CC="armeb-openwrt-linux-gcc" &&\
	export LD="armeb-openwrt-linux-ld" &&\
	export ARCH="arm" &&\
	export LINUX="$$KLIB" &&\
	export STAGING_DIR="" &&\
	$$BIN$$CC -c cloudmac_daemon.c -o cloudmac_daemon

all:
	gcc cloudmac_daemon.c -o cloudmac_daemon

clean:
	rm cloudmac_daemon 
