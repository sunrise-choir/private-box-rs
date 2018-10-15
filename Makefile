libsodium: download
	set -ex && cd libsodium && \
		echo $$SODIUM_INSTALL_DIR && \
		git fetch && \
		git checkout origin/stable && \
		rm -rf lib && \
		./autogen.sh && \
		./configure --prefix=$$SODIUM_INSTALL_DIR --disable-shared --enable-static --enable-pic --disable-pie && \
		make && \
		make install

download:
	[ -d libsodium ] || git clone https://github.com/jedisct1/libsodium libsodium

clean:
	set -ex && cd libsodium && make distclean
