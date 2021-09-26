SHELL:=/bin/bash

normal:
	gcc -g -o fotbot fotbot.c

gcov:
	gcc -fprofile-arcs -ftest-coverage -g -o fotbot-gcov fotbot.c

fuzzing:
	afl-clang-fast -g -o fotbot-fuzz fotbot.c

asan:
	clang -fsanitize=address -g -o fotbot-asan fotbot.c

all: normal gcov fuzzing asan

clean:
	rm -f fotbot fotbot-gcov fotbot-fuzz fotbot-asan fotbot.gcno fotbot.gcda
