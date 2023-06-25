#include <stdio.h>

int main(int argc, char **argv) {
	if (argc != 3) return 1;
	int a, b ;
	sscanf(argv[1], "%d", &a);
	sscanf(argv[2], "%d", &b);
	a ^= b;
	b ^= a;
	a ^= b;
	printf(" %d %d\n", a, b);
	return 0;

}
