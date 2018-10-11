libsodium:
	[ -d libsodium ] || git clone https://github.com/jedisct1/libsodium libsodium
	set -ex && cd libsodium && \
		echo $$SODIUM_INSTALL_DIR && \
		git fetch && \
		git checkout origin/stable && \
		rm -rf lib && \
		./autogen.sh && \
		./configure --prefix=$$SODIUM_INSTALL_DIR --disable-pie && \
		make && \
		make install

clean:
	rm -rf libsodium
