default: build

RSYNC=/usr/bin/rsync
HUGO=/usr/bin/env hugo

.PHONY: build

build:
	${HUGO}

server:
	${HUGO} server

publish:
	${HUGO}
	${RSYNC} -av public/* greyhat:/www/
	${RSYNC} -av public/.htaccess greyhat:/www/

