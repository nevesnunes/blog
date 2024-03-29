.POSIX:

SHELL := /bin/bash

assets-obj := $(shell find ./assets/ -type f -exec file -i {} \; | \
	grep -i image | \
	cut -d':' -f1)

# Since file extensions are not known beforehand,
# we can't write pattern rules for those cases.
# In order to only build one file at a time,
# we generate separate rules for each file.
assets-timestamp-obj := $(assets-obj:%=timestamps/%.timestamp)
$(foreach \
    prereq, \
    $(assets-obj), \
    $(eval timestamps/$(prereq).timestamp: $(prereq); \
		mkdir -p "$$(shell dirname $$@)" && \
		ect \
			-9 \
			-strip \
			--allfilters \
			--mt-deflate=2 \
			--pal_sort=30 \
			--strict $$< && \
		touch $$@) \
)

gem_dir := $(shell realpath ~/.gem)/jekyll-local
gem_bin_dir := $(shell find "$(gem_dir)" -path '*/bin' ! -path '*/gems/*' | head -n1)
jekyll-obj := \
	$(gem_bin_dir)/jekyll \
	$(gem_bin_dir)/kramdown \
	$(gem_bin_dir)/rougify
$(jekyll-obj):
	mkdir -p $(gem_dir)
	env BUNDLE_GEMFILE=Gemfile.local bundle install --path=$(gem_dir)
es5-shim := assets/js/es5-shim
es5-shim-obj := $(es5-shim).js $(es5-shim).map
$(es5-shim-obj):
	npm install --save es5-shim
	mkdir -p assets/js
	cp node_modules/es5-shim/es5-shim.* assets/js/
lunr-obj := assets/js/lunr.min.js
$(lunr-obj):
	npm install --save lunr
	mkdir -p assets/js
	cp node_modules/lunr/lunr.min.js assets/js/
dependencies: $(jekyll-obj) $(es5-shim-obj) $(lunr-obj) $(assets-timestamp-obj)

all: dependencies
	env BUNDLE_GEMFILE=Gemfile.local bundle exec jekyll serve --config _config.yml,_config.local.yml

.DEFAULT_GOAL := all
.PHONY: all dependencies
