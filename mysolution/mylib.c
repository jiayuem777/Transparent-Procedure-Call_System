/**
 * 15640 Project 1: Remote Procedure Call
 * mylib.c
 * Author: Jiayue Mao
 * Andrew ID: jiayuem
 **/

#define _GNU_SOURCE

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

#define MAXMSGLEN 100
#define FD_OFFSET 2000 // file descriptor offset
#define HEAD_LEN 16 // length of marshal header for operation call

int sockfd = 0; //socket file descriptor

//stuct for dirtreenode
struct dirtreenode {
	char *name;
	int num_subdirs;
	struct dirtreenode **subdirs;
};

// The following lines declare function pointers with the same prototype as the file operation function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd); 
ssize_t (*orig_read)(int fd, void *buf, size_t count);
ssize_t (*orig_write)(int fd, const void *buf, size_t count);
off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig___xstat)(int ver, const char * path, struct stat * stat_buf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes , off_t *basep);
struct dirtreenode* getdirtree( const char *path );
void freedirtree( struct dirtreenode* dt );

// the actual operation functions to solve different calls
int open_func(void **args);
int close_func(void **args);
ssize_t write_func(void **args); 
void *read_func(void **args); 
off_t lseek_func(void **args); 
int unlink_func(void **args); 
void *stat_func(void **args); 
void *getdirentries_func(void **args); 
struct dirtreenode* getdirtree_func(void **args);
void freetree_func(struct dirtreenode *dt);

// function used to connect to server 
void connect_to_server();
// function used to 
char *build_call_head(char *call);

// functions used for dirtreenode operations
struct dirtreenode *deserialize(char *str, size_t serial_len);
struct dirtreenode *deserialize_helper(char *str, size_t *index_addr, size_t str_len);

// wrapper functions to malloc, send and receive
void *Malloc(size_t size);
ssize_t Send(int sockfd, void *buf, size_t len, int flags);
ssize_t Recv(int sockfd, void *buf, size_t len, int flags);

/* 
 * open - replacement for the open function from libc.
 * pack the input data send to and call open_func
 * args: const char *pathname, int flags, ...
 * return: int: file descriptoe after opening a file
 */
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}
	//print a message
	fprintf(stderr, "mylib: open called for path %s\n", pathname);
	// use args to contain all the input parameter and input to open_func
	void **args = Malloc(3 * sizeof(void *));
	args[0] = (void *) pathname;
	args[1] = (void *) &flags;
	args[2] = (void *) &m;
	// call open_func
	int result = open_func(args);
	free(args);
	return result;
}

/* 
 * close - replacement for the close function from libc.
 * pack the input data send to and call close_func
 * args: int fd
 * return: output of close function
 */
int close(int fd) {
	// print some massage
	fprintf(stderr, "mylib: close called\n");
	// use args to contain all the input parameter and input to close_func
	void **args = Malloc(1 * sizeof(void *));
	args[0] = (void *) &fd;
	// call close_func
	int result = close_func(args);
	free(args);
	return result;
}

/* 
 * read - replacement for the read function from libc.
 * pack the input data send to and call read_func
 * args: int fd, void *buf, size_t count
 * return: output of read function
 */
ssize_t read(int fd, void *buf, size_t count) {
	//print some message
	fprintf(stderr, "mylib: read called\n");
	// use args to contain all the input parameter and input to read_func
	void **args = Malloc(2 * sizeof(void *));
	args[0] = (void *) &fd;
	args[1] = (void *) &count;
	// call read_func
	void *ret = read_func(args);
	free(args);
	ssize_t result = *((ssize_t *) ret);
	if (result > 0){
		memcpy(buf, ret + sizeof(ssize_t), result);
	}
	if (result < count) {
		((char *)buf)[result] = 0;
	}
	free(ret);
	return result;
}

/* 
 * write - replacement for the write function from libc.
 * pack the input data send to and call write_func
 * args: int fd, const void *buf, size_t count
 * return: output of write function
 */
ssize_t write(int fd, const void *buf, size_t count) {
	// print some message
	fprintf(stderr, "mylib: write called\n");
	// use args to contain all the input parameter and input to write_func
	void **args = Malloc(3 * sizeof(void *));
	args[0] = (void *) &fd;
	char *buf1 = Malloc(count * sizeof(char));
	memcpy(buf1, buf, count);
	args[1] = buf1;
	args[2] = (void *) &count;
	// call write_func
	ssize_t result = write_func(args);
	free(buf1); free(args);
	return result;
}

/* 
 * lseek - replacement for the lseek function from libc.
 * pack the input data send to and call lseek_func
 * args: int fd, off_t offset, int whence
 * return: output of lseek function
 */
off_t lseek(int fd, off_t offset, int whence) {
	//print some message
	fprintf(stderr, "mylib: lseek called\n");
	//use args to contain all the input parameter and input to lseek_func
	void **args = Malloc(3 * sizeof(void *));
	args[0] = (void *) &fd;
	args[1] = (void *) &offset;
	args[2] = (void *) &whence;
	//call lseek_func
	off_t result = lseek_func(args);
	free(args); 
	return result;
}

/* 
 * __xstat - replacement for the __xstat function from libc.
 * pack the input data send to and call stat_func
 * args: int ver, const char * path, struct stat * stat_buf
 * return: output of stat function
 */
int __xstat(int ver, const char * path, struct stat * stat_buf) {
	//print some message
	fprintf(stderr, "mylib: xstat called\n");
	//use args to contain all the input parameter and input to stat_func
	void **args = Malloc(2 * sizeof(void *));
	args[0] = (void *) &ver;
	char *ppath = Malloc(strlen(path) + 1);
	memcpy(ppath, path, strlen(path) + 1);
	args[1] = ppath;
	//call stat_func
	void *ret = stat_func(args);
	free(ppath); free(args);
	//the first 4 bytes of ret is return value
	int result = *((int *) ret);
	//copy the last bytes to stat_buf
	memcpy(stat_buf, ret + sizeof(int), sizeof(struct stat));
	free(ret);
	return result;
}

/* 
 * unlink - replacement for the unlink function from libc.
 * pack the input data send to and call unlink_func
 * args: const char *pathname
 * return: output of unlink function
 */
int unlink(const char *pathname) {
	fprintf(stderr, "mylib: unlink called\n");
	// use args to contain all the input parameters and input to unlink_func
	void **args = Malloc(1 * sizeof(void *));
	char *path = Malloc(strlen(pathname) + 1);
	memcpy(path, pathname, strlen(pathname) + 1);
	args[0] = path;
	int result = unlink_func(args);
	free(path); free(args); 
	return result;
}

/* 
 * getdirentries - replacement for the getdirentries function from libc.
 * pack the input data send to and call getdirentries_func
 * args: int fd, char *buf, size_t nbytes , off_t *basep
 * return: output of getdtrentries function
 */
ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t *basep) {
	fprintf(stderr, "mylib: getdirentries called\n");
	// use args to contain all the input parameters and input to getdirentries_func
	void **args = Malloc(3 * sizeof(void *));
	args[0] = (void *) &fd;
	args[1] = (void *) &nbytes;
	args[2] = (void *) basep;
	void *ret = getdirentries_func(args);
	free(args);
	//the first 8 bytes are return value
	ssize_t result = *((ssize_t *) ret);
	//the next bytes are content of basep
	*basep = *((off_t *) (ret + sizeof(result)));
	//copy last bytes of ret to buf
	memcpy(buf, ret + sizeof(result) + sizeof(off_t), nbytes);
	free(ret);
	return result;
}

/* 
 * getdirtree - replacement for the getdirtree function from libc.
 * pack the input data send to and call getdirtree_func
 * args: const char *path
 * return: output of getdirtree function
 */
struct dirtreenode* getdirtree( const char *path ) {
	fprintf(stderr, "mylib: getdirtree called\n");
	// use args to contain all the input parameters and input to getdirtree_func
	void **args = Malloc(1 * sizeof(void *));
	char *ppath = Malloc(strlen(path) + 1);
	memcpy(ppath, path, strlen(path) + 1);
	args[0] = ppath;
	struct dirtreenode *ret = getdirtree_func(args);
	free(args); free(ppath);
	return ret;
}

/* 
 * freedirtree - replacement for the freedirtree function from libc.
 * pack the input data send to and call freedirtree_func
 * args: struct dirtreenode* dt
 * return: void
 */
void freedirtree( struct dirtreenode* dt ) {
	fprintf(stderr, "mylib: freedirtree called\n");
	freetree_func(dt);
	return;
}

/* 
 * _init - automatically called when program is started.
 */
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
	fprintf(stderr, "Init mylib\n");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig_read = dlsym(RTLD_NEXT, "read");
	orig_write = dlsym(RTLD_NEXT, "write");
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	orig_lseek = dlsym(RTLD_NEXT, "lseek");
	orig___xstat = dlsym(RTLD_NEXT, "__xstat");
	orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
	connect_to_server(); //connect to server
}

/* 
 * _fini - automatically called when program is started.
 */
void _fini(void) {
	orig_close(sockfd);
}

/* 
 * connect_to_server - connect to the server and set the global variable sockfd
 * args: none
 * return: none
 */
void connect_to_server() {
	char *serverip;
	char *serverport;
	unsigned short port;
	struct sockaddr_in srv;
	// Get environment variable indicating the ip address of the server
	serverip = getenv("server15440");
	if (serverip) ;
	else {
		serverip = "127.0.0.1";
	}
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) ;
	else {
		serverport = "35797";
	}
	port = (unsigned short)atoi(serverport);

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to point to server
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
	srv.sin_port = htons(port);			// server port

	// actually connect to the server
	int rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
}

/* 
 * build_call_head - build the head of marshaled sending data
 * Length of head is set to HEAD_LEN
 * Content is string of file operation call
 * args: char *call
 * return: char *: string of head
 */
char *build_call_head(char *call) {
	char *call_head = Malloc(HEAD_LEN);
	memcpy(call_head, call, strlen(call));
	int i = 0;
	for (i = strlen(call); i < HEAD_LEN; i++) {
		call_head[i] = 0;
	}
	return call_head;
}

/* 
 * open_func - actual operation function for open call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to open() function
 * args: void **args: parameters for open
 * return: int: return result of open
 */
int open_func(void **args) {
	char *call = build_call_head("open");
	//get input parameters from args
	char *pathname = (char *)args[0];
	int send_size = HEAD_LEN + strlen(pathname) + 1 + sizeof(int) * 3;
	char *send_buf = Malloc(send_size);
	//msg_len is the length of string contains all the input parameters
	int msg_len = strlen(pathname) + 1 + sizeof(int) * 2;
	
	// marshal data for sending
	// contain: operation call name, msg_len, input parameters
	memcpy(send_buf, call, HEAD_LEN); free(call);
	memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int), pathname, strlen(pathname) + 1);
	memcpy(send_buf + HEAD_LEN + sizeof(int) + strlen(pathname) + 1, args[1], sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int) + strlen(pathname) + 1 + sizeof(int), args[2], sizeof(int));
	//send to server
	Send(sockfd, send_buf, send_size, 0);
	free(send_buf);

	int rcv_size = 2 * sizeof(int); //receive buffer size
	char *rcv_buf = Malloc(rcv_size);
	Recv(sockfd, rcv_buf, rcv_size, 0);	// receive from server

	int result = *((int *) rcv_buf); //first 4 bytes are return value
	errno = *((int *) (rcv_buf + sizeof(int))); // next four bytes sre errno
	free(rcv_buf);
	
	// if open result smaller than offset, call local orig_open
	if (result < FD_OFFSET) {
		result = orig_open(pathname, *((int *)args[1]), *((int *)args[2]));
	}

	return result;
}

/* 
 * close_func - actual operation function for close call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to close() function
 * args: void **args: parameters for close
 * return: int: return result of close
 */
int close_func(void **args) {
	char *call = build_call_head("close");

	int fd = *((int *) args[0]);
	int result = 0;

	// if file descriptor is smaller than offset, close locally
	if (fd < FD_OFFSET) {
		result = orig_close(fd);
	} else {

		int send_size = HEAD_LEN + sizeof(int) * 2; //send buffer size
		char *send_buf = Malloc(send_size);
		int msg_len = sizeof(int);
		// marshal data for sending
		// contain: operation call name, msg_len, input parameters
		memcpy(send_buf, call, HEAD_LEN); 
		memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int), &fd, sizeof(int));
		
		Send(sockfd, send_buf, send_size, 0); //send to server
		free(send_buf);

		int rcv_size = 2 * sizeof(int); //receive buffer size
		char *rcv_buf = Malloc(rcv_size);
		Recv(sockfd, rcv_buf, rcv_size, 0);	// receive massage from server

		result = *((int *) rcv_buf); // first 4B is return value
		errno = *((int *) (rcv_buf + sizeof(int))); // next 4B is errno
		free(rcv_buf);
	}
	free(call);
	return result;
}

/* 
 * write_func - actual operation function for write call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to write() function
 * args: void **args: parameters for write
 * return: int: return result of write
 */
ssize_t write_func(void **args) {
	char *call = build_call_head("write");
	
	//get input parameters from args
	int fd = *((int *) args[0]);
	size_t count = *((size_t *) args[2]);
	void *write_buf = args[1];
	ssize_t result = 0;

	// if file descriptor is smaller than offset, write locally
	if (fd < FD_OFFSET) {
		result = orig_write(fd, write_buf, count);
	} else {
		//send buffer size
		int send_size = HEAD_LEN + sizeof(int) * 2 + sizeof(size_t) + count;
		char *send_buf = Malloc(send_size);
		int msg_len = sizeof(int) + sizeof(size_t) + count;
		// marshal data for sending
		// contain: operation call name, msg_len, input parameters
		memcpy(send_buf, call, HEAD_LEN);
		memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int), &fd, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int) + sizeof(int), &count, sizeof(size_t));
		memcpy(send_buf + HEAD_LEN + sizeof(int) + sizeof(int) + sizeof(size_t), write_buf, count);

		Send(sockfd, send_buf, send_size, 0); //send to server
		free(send_buf);
		
		int rcv_size = sizeof(ssize_t) + sizeof(int); //receive buffer size
		char *rcv_buf = Malloc(rcv_size); 
		Recv(sockfd, rcv_buf, rcv_size, 0);	// get message

		result = *((ssize_t *)rcv_buf); //return value
		errno = *((int *) (rcv_buf + sizeof(ssize_t))); //errno
		free(rcv_buf);
	}
	free(call);
	return result;
}

/* 
 * read_func - actual operation function for read_ call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to read_() function
 * args: void **args: parameters for read (fd and count)
 * return: void *: the address of a chunk of block, where
 * first 8 bytes contain the read return value,
 * the last count bytes contain the read content
 */
void *read_func(void **args) {
	char *call = build_call_head("read");

	//get massage from args
	int fd = *((int *) args[0]);
	size_t count = *((size_t *) args[1]);
	size_t read_size = sizeof(ssize_t) + count + 1;
	char *read_buf = Malloc(read_size);

	// if file descriptor is smaller than offset, write locally
	if (fd < FD_OFFSET) {
		char *orig_read_buf = Malloc(count);
		ssize_t result = orig_read(fd, orig_read_buf, count);
		memcpy(read_buf, &result, sizeof(ssize_t));
		memcpy(read_buf + sizeof(ssize_t), orig_read_buf, count);
		free(orig_read_buf);

	} else {
		//send buffer size
		int send_size = HEAD_LEN + sizeof(int) * 2 + sizeof(size_t);
		char *send_buf = Malloc(send_size);
		int msg_len = sizeof(int) + sizeof(size_t);
		// marshal data for sending
		// contain: operation call name, msg_len, input parameters
		memcpy(send_buf, call, HEAD_LEN);
		memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int), &fd, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int) * 2, &count, sizeof(size_t));
		
		Send(sockfd, send_buf, send_size, 0); //send to server
		free(send_buf);

		/* receive from server twice
		 * 1st: get return value and errno
		 * 2nd: get read buffer
		 */
		int rcv_size1 = sizeof(ssize_t) + sizeof(int); //1st receive buffer size
		char *rcv_buf1 = Malloc(rcv_size1);
		Recv(sockfd, rcv_buf1, rcv_size1, 0);	//recv 1
		ssize_t result = *((ssize_t *)rcv_buf1); //return value
		errno = *((int *) (rcv_buf1 + sizeof(ssize_t))); //errno
		free(rcv_buf1);
		memcpy(read_buf, &result, sizeof(ssize_t));

		//if read success, server send back read buffer
		if (result > 0) {
			size_t rcv_size2 = result; //2nd receive buffer size
			char *rcv_buf2 = Malloc(rcv_size2);
			Recv(sockfd, rcv_buf2, rcv_size2, 0); //recv 2
			memcpy(read_buf + sizeof(ssize_t), rcv_buf2, result);
			free(rcv_buf2);
		} 
	}
	free(call);
	//return return value and read buffer content to read()
	return read_buf;
}

/* 
 * lseek_func - actual operation function for lseek call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to lseek() function
 * args: void **args: parameters for lseek
 * return: off_t: return value of lseek
 */
off_t lseek_func(void **args) {
	char *call = build_call_head("lseek");

	int fd = *((int *) args[0]);
	off_t offset = *((off_t *) args[1]);
	int whence = *((int *) args[2]);
	off_t result = 0;
	
	// if file descriptor is smaller than offset, lseek locally
	if (fd < FD_OFFSET) {
		result = orig_lseek(fd, offset, whence);
	} else {
		int send_size = HEAD_LEN + sizeof(int) * 2 + sizeof(off_t) + sizeof(int);
		char *send_buf = Malloc(send_size);
		int msg_len = sizeof(int) + sizeof(off_t) + sizeof(int);
		// marshal data for sending
		// contain: operation call name, msg_len, input parameters
		memcpy(send_buf, call, HEAD_LEN);
		memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int), &fd, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int) * 2, &offset, sizeof(off_t));
		memcpy(send_buf + HEAD_LEN + sizeof(int) * 2 + sizeof(off_t), &whence, sizeof(int));

		Send(sockfd, send_buf, send_size, 0); //send to server
		free(send_buf);

		int rcv_size = sizeof(off_t) + sizeof(int); //receive buffer size
		char *rcv_buf = Malloc(rcv_size);
		Recv(sockfd, rcv_buf, rcv_size, 0);	// get message

		result = *((off_t *)rcv_buf);
		errno = *((int *) (rcv_buf + sizeof(off_t)));
		free(rcv_buf);
	}
	return result;
}

/* 
 * unlink_func - actual operation function for unlink call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to unlink() function
 * args: void **args: parameters for unlink
 * return: int: return value of unlink
 */
int unlink_func(void **args) {
	char *call = build_call_head("unlink");

	//get input parameters from args
	char *pathname = (char *) args[0];
	fprintf(stderr, "unlink path: %s\n", pathname);
	int send_size = HEAD_LEN + sizeof(int) + strlen(pathname) + 1;
	char *send_buf = Malloc(send_size);
	int msg_len = strlen(pathname) + 1;
	// marshal data for sending
	// contain: operation call name, msg_len, input parameters
	memcpy(send_buf, call, HEAD_LEN); free(call);
	memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int), pathname, strlen(pathname) + 1);

	Send(sockfd, send_buf, send_size, 0); //send to server
	free(send_buf);

	int rcv_size = 2 * sizeof(int); //receive buffer size
	char *rcv_buf = Malloc(rcv_size);
	Recv(sockfd, rcv_buf, rcv_size, 0);	// get message

	int result = *((int *)rcv_buf);
	errno = *((int *) (rcv_buf + sizeof(int)));
	free(rcv_buf);
	
	// if unlink failed, try locally
	if (result == -1) {
		result = orig_unlink(pathname);
	}
	return result;
}

/* 
 * stat_func - actual operation function for stat call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to stat() function
 * args: void **args: parameters for stat
 * return: void *: the address of a chunk of block, where
 * first 4 bytes contain the stat return value,
 * the last bytes contain the struct stat
 */
void *stat_func(void **args) {
	char *call = build_call_head("stat");

	// get input parameters from args
	int ver = *((int *) args[0]);
	char *path = (char *) args[1];
	fprintf(stderr, "stat ver: %d\n", ver);
	fprintf(stderr, "stat path: %s\n", path);
	int send_size = HEAD_LEN + sizeof(int) * 2 + strlen(path) + 1;
	char *send_buf = Malloc(send_size);
	int msg_len = sizeof(int) + strlen(path) + 1;
	// marshal data for sending
	// contain: operation call name, msg_len, input parameters
	memcpy(send_buf, call, HEAD_LEN); free(call);
	memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int), &ver, sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int) * 2, path, strlen(path) + 1);

	Send(sockfd, send_buf, send_size, 0); //send to server
	free(send_buf);

	int rcv_size = sizeof(int) + sizeof(int) + sizeof(struct stat); //receive buffer size
	char *rcv_buf = Malloc(rcv_size);
	Recv(sockfd, rcv_buf, rcv_size, 0); //receive from server

	int result = *((int *)rcv_buf); //return value
	errno = *((int *) (rcv_buf + sizeof(int))); //errno
	//return content to stat() contain return value and stat_buf
	char *ret_buf = Malloc(sizeof(int) + sizeof(struct stat));
	
	//if remote operation failed, try locally
	if (result == -1) {
		struct stat *stat_buf = (struct stat *) Malloc(sizeof(struct stat));
		result = orig___xstat(ver, path, stat_buf);
		memcpy(ret_buf + sizeof(int), stat_buf, sizeof(struct stat));
		free(stat_buf);
	} else {
		memcpy(ret_buf + sizeof(int), rcv_buf + 2*sizeof(int), sizeof(struct stat));
	}
	memcpy(ret_buf, &result, sizeof(int));
	free(rcv_buf);
	return ret_buf;
}

/* 
 * getdirentries_func - actual operation function for getdirentries call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * return result to getdirentries() function
 * args: void **args: parameters for getdirentries
 * return: void *: the address of a chunk of block, where
 * first 8 bytes contain the getdirentries return value,
 * the next 8 bytes contain the content of basep
 * the last nbytes contain received buf content
 */
void *getdirentries_func(void **args) {
	char *call = build_call_head("getdirentries");

	//get input parameters from args
	int fd = *((int *) args[0]);
	size_t nbytes = *((size_t *) args[1]);
	off_t *basep = (off_t *) args[2];

	//return content to getdirentries contain return value, basep content, buf content
	size_t ret_size = sizeof(ssize_t) + sizeof(off_t) + nbytes;
	char *ret = Malloc(ret_size);

	// if file descriptor is smaller than offset, getdirentries locally
	if (fd < FD_OFFSET) {
		char *orig_get_buf = Malloc(nbytes);
		ssize_t result = orig_getdirentries(fd, orig_get_buf, nbytes, basep);
		memcpy(ret, &result, sizeof(result));
		memcpy(ret + sizeof(result), basep, sizeof(off_t));
		memcpy(ret + sizeof(result) + sizeof(off_t), orig_get_buf, nbytes);
		free(orig_get_buf);
	} else {

		size_t send_size = HEAD_LEN + sizeof(int) * 2 + sizeof(size_t) + sizeof(off_t);
		char *send_buf = Malloc(send_size);
		int msg_len = sizeof(int) + sizeof(size_t) + sizeof(off_t);
		// marshal data for sending
		// contain: operation call name, msg_len, input parameters
		memcpy(send_buf, call, HEAD_LEN);
		memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int), &fd, sizeof(int));
		memcpy(send_buf + HEAD_LEN + sizeof(int) * 2, &nbytes, sizeof(size_t));
		memcpy(send_buf + HEAD_LEN + sizeof(int) * 2 + sizeof(size_t), basep, sizeof(off_t));

		Send(sockfd, send_buf, send_size, 0); //send to server
		free(send_buf);

		//receive buffer size
		size_t rcv_size = sizeof(ssize_t) + sizeof(int) + sizeof(off_t) + nbytes;
		char *rcv_buf = Malloc(rcv_size);
		Recv(sockfd, rcv_buf, rcv_size, 0);	// receive from server

		ssize_t result = *((ssize_t *)rcv_buf); //return value
		errno = *((int *) (rcv_buf + sizeof(result))); //errno
		
		memcpy(ret, rcv_buf, sizeof(result));
		memcpy(ret + sizeof(result), rcv_buf + sizeof(result) + sizeof(int), sizeof(off_t) + nbytes);
		free(rcv_buf);
	}
	free(call);
	return ret;
}

/* 
 * getdirtree_func - actual operation function for getdirtree call
 * marshal data, send to server 
 * receive data from server, unmarshal data
 * deserialize the received string to dirtreenode
 * return result to getdirtree() function
 * args: void **args: parameters for getdirtree
 * return: struct dirtreenode*: return value of getdirtree
 */
struct dirtreenode* getdirtree_func(void **args) {
	char *path = (char *) args[0];
	//if path is NULL, set errno
	if (path == NULL) {
		errno = EADDRNOTAVAIL;
		return NULL;
	}
	char *call = build_call_head("getdirtree");
	int send_size = HEAD_LEN + sizeof(int) + strlen(path) + 1;
	char *send_buf = Malloc(send_size);
	int msg_len = strlen(path) + 1;
	// marshal data for sending
	// contain: operation call name, msg_len, input parameters
	memcpy(send_buf, call, HEAD_LEN); free(call);
	memcpy(send_buf + HEAD_LEN, &msg_len, sizeof(int));
	memcpy(send_buf + HEAD_LEN + sizeof(int), path, strlen(path) + 1);
	
	Send(sockfd, send_buf, send_size, 0); //send to server
	free(send_buf);

	/* receive from server twice
	 * 1st: get length of serialize string and errno
	 * 2nd: get serialize string
	 */
	int rcv_size1 = sizeof(size_t) + sizeof(int); //1st receive buffer size
	char *rcv_buf1 = Malloc(rcv_size1);
	Recv(sockfd, rcv_buf1, rcv_size1, 0); //recv 1
	size_t serial_len = *((size_t *) rcv_buf1); // get serialize string length
	errno = *((int *) (rcv_buf1 + sizeof(size_t)));
	free(rcv_buf1);

	size_t rcv_size2 = serial_len; //2nd receive buffer size
	char *rcv_buf2 = Malloc(rcv_size2);
	Recv(sockfd, rcv_buf2, rcv_size2, 0); //recv 2

	//deserialize string to dirtree
	struct dirtreenode *root = deserialize(rcv_buf2, serial_len);
	free(rcv_buf2);

	return root;
}

/* 
 * freetree_func - actual operation function for freetree call
 * free all the dirtreenode of dt and all the subdirs
 * args: struct dirtreenode *dt
 * return: void
 */
void freetree_func(struct dirtreenode *dt) {
	if (dt == NULL) {
		return;
	}
	int i = 0;
	for (i = 0; i < dt->num_subdirs; i++) {
		freetree_func(dt->subdirs[i]);
	}
	free(dt->name);
	free(dt->subdirs);
	free(dt);
}

/* 
 * deserialize - deserialize a string to dirtreenode
 * args: char *str: input string; size_t serial_len: length of string
 * return: struct dirtreenode *: address of root dirtreenode
 */
struct dirtreenode *deserialize(char *str, size_t serial_len) {
	size_t *index_addr = Malloc(sizeof(size_t));
	*index_addr = 0;
	struct dirtreenode *root = deserialize_helper(str, index_addr, serial_len);
	free(index_addr);
	return root;
}

/* 
 * deserialize_helper - helper function to deserialize a string to dirtreenode
 * args: char *str: input string
 *       size_t *index_addr: a point pointed to a position in the string
 *       size_t str_len: the length of the input string
 * return: struct dirtreenode *: address of root dirtreenode 
 * of the substring of input string whose start position 
 * is determined by size_t *index_addr
 */
struct dirtreenode *deserialize_helper(char *str, size_t *index_addr, size_t str_len) {
	size_t index = *index_addr;
	if (index >= str_len) {
		return NULL;
	}
	// if encounter terminator, return NULL
	if (*(str + index) == '\0') {
		*index_addr += 1;
		return NULL;
	}
	struct dirtreenode *node = Malloc(sizeof(struct dirtreenode));
	int len = strlen(str + index) + 1;
	node->name = (char *) Malloc(len);
	memcpy(node->name, str + index, len); //copy node name from string
	memcpy((void *) &(node->num_subdirs), str + index + len, sizeof(int)); //copy subdir numbers from string
	node->subdirs = calloc(node->num_subdirs, sizeof(struct dirtreenode *));
	int i = 0;
	// pointer pointed to next node in the string
	index += len + sizeof(int);
	*index_addr = index;
	//recurse for each child node
	for (i = 0; i < node->num_subdirs; i++) {
		node->subdirs[i] = deserialize_helper(str, index_addr, str_len);
	}
	return node;
}

/*
 * Malloc - wrapper function for malloc
 */
void *Malloc(size_t size) {
	void *ret = malloc(size);
	if (ret == NULL) {
		fprintf(stderr, "malloc failed\n");
		err(1, 0);
	}
	return ret;
}

/*
 * Send - wrapper function for send
 * Use loop to send chunk of data sequentialy
 */
ssize_t Send(int sockfd, void *buf, size_t len, int flags) {
	size_t sdnum = 0;
	void *tmp = buf;
	while (len > 0) {
		sdnum = send(sockfd, tmp, len, flags);
		if (sdnum < 0) {
			fprintf(stderr, "send failed\n");
			err(1, 0);
			break;
		}
		//fprintf(stderr, "len: %ld\n", len);
		len -= sdnum;
		tmp += sdnum;
	}
	return len;
}

/*
 * Recv - wrapper function for recv
 * Use loop to receive chunk of data sequentialy
 */
ssize_t Recv(int sockfd, void *buf, size_t len, int flags) {
	size_t rvnum = 0;
	void *tmp = buf;
	while (len > 0) {
		rvnum = recv(sockfd, tmp, len, flags);
		if (rvnum < 0) {
			fprintf(stderr, "recv failed\n");
			err(1, 0);
			break;
		}
		len -= rvnum;
		tmp += rvnum;
	}
	return len;
}



