main: main.c
	gcc --std=c99 main.c -Wall -Wextra -Werror -o main

clean:
	rm -f main