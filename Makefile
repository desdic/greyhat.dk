default: build

RSYNC=/usr/bin/rsync
HUGO=/usr/local/bin/hugo

.PHONY: publish
=======
.PHONY: build

build:
	${HUGO}

server:
	${HUGO} server

publish:
	${HUGO}
	${RSYNC} -av public/* greyhat:/www/

