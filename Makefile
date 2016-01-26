default: publish

RSYNC=/usr/bin/rsync
HUGO=/usr/local/bin/hugo

.PHONY: publish

publish:
	${HUGO}
	${RSYNC} -av public/* greyhat:/www/

