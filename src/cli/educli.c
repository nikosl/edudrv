#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "educmd.h"

int main(int argc, char **argv)
{
	int fd = 0;
	int status = 0;
	uint32_t value = 0;

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "Usage: %s <devfile> <cmd> [<arg>]\n", argv[0]);
		return 0;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open device failed");
		return fd;
	}

	if (strcmp(argv[2], "check") == 0) {
		value = strtoll(argv[3], 0, 0);
		status = ioctl(fd, EDUCMD_LIVENESS, &value);

		printf("ioctl returned %d, Liveness Register: %d\n", status,
		       value);
	} else if (strcmp(argv[2], "calc") == 0) {
		value = strtoll(argv[3], 0, 0);
		status = ioctl(fd, EDUCMD_FACTORIAL, &value);

		printf("ioctl returned %d, Factorial Register: %d\n", status,
		       value);
	} else {
		fprintf(stderr, "%s is not a valid cmd\n", argv[2]);
	}

	close(fd);
	return 0;
}
