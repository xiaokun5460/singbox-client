BINARY      = singbox-client
INSTALL_DIR = /usr/local/bin
SERVICE     = singbox-client

.PHONY: build css deploy restart status logs clean

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) .

css:
	./tailwindcss -i web/static/css/input.css -o web/static/css/tailwind.min.css --minify

deploy: build
	sudo systemctl stop $(SERVICE)
	sudo cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	sudo systemctl start $(SERVICE)
	@echo "deployed and restarted"

restart:
	sudo systemctl restart $(SERVICE)

status:
	@systemctl status $(SERVICE) --no-pager

logs:
	sudo journalctl -u $(SERVICE) -f

clean:
	rm -f $(BINARY)
