install:
	gcc capture.c -o capture -g
	ln -s -f `pwd`/capture /usr/bin/capture
	ln -s -f `pwd`/shaniffer.sh /usr/bin/shaniffer
	ln -s -f `pwd`/shaniffer.sh /usr/bin/shaniffer.sh
	ln -s -f `pwd`/shailter.sh /usr/bin/shailter.sh
