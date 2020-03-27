
#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <errno.h>

int main(int argc, char**argv) {
    int fd = -10;
    size_t nbytes = 10;
    off_t *basep = malloc(sizeof(off_t));
    *basep = 1024;
    char *buf = (char *) malloc(nbytes * sizeof(char));
    *basep = 0;
    ssize_t result = getdirentries(fd, buf, nbytes, basep);
    fprintf(stderr, "test result: %ld\n", result);
    
    return 0;

}
