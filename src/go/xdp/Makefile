.PHONY:
APP = parser_packet

$(APP): %:
	cd ./% && go generate && go build -o $@

clean:
	rm -rf $(APP)/$(APP)