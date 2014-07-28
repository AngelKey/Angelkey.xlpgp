default: build
all: build

ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp

lib/%.js: src/%.iced
	$(ICED) -c -o `dirname $@` $<

$(BUILD_STAMP): \
	lib/const.js \
	lib/encrypt.js \
	lib/header.js \
	lib/index.js \
	lib/io.js \
	lib/main.js \
	lib/packet.js \
	lib/stubs.js
	date > $@

clean:
	find lib -type f -name *.js -exec rm {} \;

build: $(BUILD_STAMP)

setup:
	npm install -d

test:
	$(ICED) test/run.iced

.PHONY: test setup

