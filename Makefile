#

all:
	@echo "Usage: make clean" ; exit 1

clean:
	@find . \( -name '*~' -or -name '#*' -or -name core \) -print0 | xargs -0 rm

push: 	clean
	git add -A && git commit -a && git push

pull:	clean
	git pull


