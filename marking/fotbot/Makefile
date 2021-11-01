SHELL:=/bin/bash

normal:
	gcc -g -o fotbot fotbot.c

fault2:
	gcc -g -o fotbot_fault2 fotbot_fault2.c

gcov:
	gcc -fprofile-arcs -ftest-coverage -g -o fotbot-gcov fotbot.c

fuzzing:
	afl-clang-fast -g -o fotbot-fuzz fotbot.c

asan:
	clang -fsanitize=address -g -o fotbot-asan fotbot.c

all: normal gcov fuzzing asan fault2

clean:
	rm -f fotbot fotbot-gcov fotbot-fuzz fotbot-asan fotbot.gcno fotbot.gcda
