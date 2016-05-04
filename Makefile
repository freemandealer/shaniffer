install:
	gcc shapture.c -o shapture
	ln -s -f `pwd`/shapture /usr/bin/shapture
	ln -s -f `pwd`/shailter.sh /usr/bin/shailter
