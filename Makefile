P4C ?= p4c-bm2-ss
PYTHON ?= python3

BUILD_DIR := build
P4_SOURCE := p4/count_min_sketch.p4
P4_JSON := $(BUILD_DIR)/count_min_sketch.json
P4INFO := $(BUILD_DIR)/count_min_sketch.p4info.txtpb

.PHONY: build test clean

build: $(P4_JSON) $(P4INFO)

$(P4_JSON) $(P4INFO) &: $(P4_SOURCE)
	@mkdir -p $(BUILD_DIR)
	$(P4C) --Werror --p4v 16 \
		--p4runtime-files $(P4INFO) \
		-o $(P4_JSON) $(P4_SOURCE)

test: build
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf -- $(BUILD_DIR)
	rm -rf -- tests/__pycache__
