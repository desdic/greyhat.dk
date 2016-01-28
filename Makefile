default: build

RSYNC=/usr/bin/rsync
HUGO=/usr/local/bin/hugo

.PHONY: build

build:
	${HUGO}

server:
	${HUGO} server

publish:
	${HUGO}
	${RSYNC} -av public/* greyhat:/www/

