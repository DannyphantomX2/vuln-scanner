# Makefile for the Vulnerability Scanner

# Default values
TARGET ?= 127.0.0.1
PORTS  ?= 1-1024
JSON   ?= false

# Python interpreter
PYTHON = python3

.PHONY: all install run clean

all: install run

# Install dependencies
install:
	@echo "Installing dependencies..."
	$(PYTHON) -m pip install -r requirements.txt

# Run the scanner
run:
	@echo "Running scanner on $(TARGET) ports $(PORTS)..."
	@if [ "$(JSON)" = "true" ]; then \
		$(PYTHON) main.py --target $(TARGET) --ports $(PORTS) --json; \
	else \
		$(PYTHON) main.py --target $(TARGET) --ports $(PORTS); \
	fi

# Clean generated files
clean:
	@echo "Cleaning up generated files..."
	rm -f scan_*.pdf scan_*.json
