/**
 * 15640 Project 1: Remote Procedure Call
 * server.c
 * Author: Jiayue Mao
 * Andrew ID: jiayuem
 **/

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <signal.h>


#define MAXMSGLEN 100
#define FD_OFFSET 2000 // file descriptor offset
#define HEAD_LEN 16 // length of marshal header for operation call

//stuct for dirtreenode
struct dirtreenode {
	char *name;
	int num_subdirs;
	struct dirtreenode **subdirs;
};

// functions regards dirtreenode operations
char *combine_strs(char **strs, size_t *lens, int num);
char *serialize(struct dirtreenode *node, size_t *len);
void freedirtree( struct dirtreenode* dt );

// handler function to solve SIGCHLD signal
void handle_sigchld(int sig);

// functions to deal with different operation calls from clients
void open_func(int sessfd, int msg_len);
void close_func(int sessfd, int msg_len);
void write_func(int sessfd, int msg_len);
void read_func(int sessfd, int msg_len);
void lseek_func(int sessfd, int msg_len);
void unlink_func(int sessfd, int msg_len);
void getdirentries_func(int sessfd, int msg_len);
void getdirtree_func(int sessfd, int msg_len);

// wrapper functions for malloc, send and recv
void *Malloc(size_t size);
ssize_t Send(int sockfd, void *buf, size_t len, int flags);
ssize_t Recv(int sockfd, void *buf, size_t len, int flags);

/* 
 * combine_strs - combine multiple strings to a single string.
 * args: char **strs: input multiple strings
 *       size_t *lens: the length of the input strings
 *       int num: the num of input strings
 * return: the combined string
 */
char *combine_strs(char **strs, size_t *lens, int num) {
	if (num == 1) {
		return strs[0];
	}
	int i = 0;
	size_t sum_size = 0;
	for (i = 0; i < num; i++) {
		sum_size += lens[i];
	}
	char *combine = Malloc(sum_size * sizeof(char));
	//fprintf(stderr, "malloc combine\n");
	size_t p = 0;
	for (i = 0; i < num; i++) {
		memcpy(combine + p, strs[i], lens[i]);
		fprintf(stderr, "%s\n", combine+p);
		p += lens[i];
		free(strs[i]);
	}
	return combine;
}

/* 
 * serialize - serialize of a dirtree.
 * args: struct dirtreenode *node: the root node of a dirtree
 *       size_t *len: the int pointer contain the length of the serialized string
 * return: the serialized string
 */
char *serialize(struct dirtreenode *node, size_t *len) {
	//base case for recursion:
	//if node is NULL, add terminator to stirng
	if (node == NULL) {
		char *ret = Malloc(sizeof(char));
		*ret = 0;
		*len = 1;
		return ret;
	}
	int num_sub = node->num_subdirs;
	char **strs = Malloc((num_sub + 1) * sizeof(char *));
	size_t *lens = Malloc((num_sub + 1) * sizeof(size_t));
	strs[0] = Malloc(strlen(node->name) + 1 + sizeof(int));
	memcpy(strs[0], node->name, strlen(node->name) + 1);
	memcpy(strs[0] + strlen(node->name) + 1, &num_sub, sizeof(int));
	lens[0] = strlen(node->name) + 1 + sizeof(int);

	//recurse all the child nodes
	int i = 0;
	for (i = 1; i <= num_sub; i++) {
		size_t *sublen = Malloc(sizeof(size_t));
		strs[i] = serialize(node->subdirs[i - 1], sublen);
		lens[i] = *sublen;
		free(sublen);
	}

	//combine string for parent node and string for all the child nodes
	char *serial = combine_strs(strs, lens, num_sub + 1);
	*len = 0;
	for (i = 0; i <= num_sub; i++) {
		*len += lens[i];
	}
	free(strs);
	free(lens);
	return serial;
}

/* 
 * freedirtree - free a dirtree.
 * args: struct dirtreenode *dt: the root node of the dirtree
 * return: void
 */
void freedirtree(struct dirtreenode *dt) {
	if (dt == NULL) {
		return;
	}
	int i = 0;
	for (i = 0; i < dt->num_subdirs; i++) {
		freedirtree(dt->subdirs[i]);
	}
	free(dt->name);
	free(dt->subdirs);
	free(dt);
}

/* 
 * handle_sigchld - handler function of SIGCHLD signal.
 * args: int sig: input signal
 * return: void
 */
void handle_sigchld(int sig) {
  int saved_errno = errno;
  while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
  errno = saved_errno;
}

/* 
 * open_func - operation function when input call is "open".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void open_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameters from receive buffer
	int pathname_len = strlen(rcv_buf) + 1;
	char *pathname = Malloc(pathname_len * sizeof(char));
	memcpy(pathname, rcv_buf, pathname_len);
	int flags = *((int *) (rcv_buf + pathname_len));
	int m = *((int *) (rcv_buf + pathname_len + sizeof(int)));
	free(rcv_buf);
	
	//call open and add file descriptor offset
	int result = open(pathname, flags, m) + FD_OFFSET; 
	free(pathname);

	//send return value and errno back to client
	char send_buf[2 * sizeof(int)];
	memcpy(send_buf, &result, sizeof(int));
	memcpy(send_buf + sizeof(int), &errno, sizeof(int));
	int sd = Send(sessfd, send_buf, 2 * sizeof(int), 0);

}

/* 
 * close_func - operation function when input call is "close".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void close_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client
	//get input parameters from receive buffer
	int fd = *((int *) rcv_buf) - FD_OFFSET;

	//call close
	int result = close(fd);
	free(rcv_buf);
	
	//send return value and errno back to client
	char send_buf[2 * sizeof(int)];
	memcpy(send_buf, &result, sizeof(int));
	memcpy(send_buf + sizeof(int), &errno, sizeof(int));
	int sd = Send(sessfd, send_buf, 2 * sizeof(int), 0);
}

/* 
 * write_func - operation function when input call is "write".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void write_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameters from receive buffer
	int fd = *((int *) rcv_buf) - FD_OFFSET;
	size_t count = *((size_t *) (rcv_buf + sizeof(int)));
	char *write_buf = Malloc(count * sizeof(char));
	memcpy(write_buf, rcv_buf + sizeof(int) + sizeof(size_t), count);
	free(rcv_buf);

	//call write
	ssize_t result = write(fd, write_buf, count);
	free(write_buf);

	//send return value and errno back to client
	char send_buf[sizeof(result) + sizeof(int)];
	memcpy(send_buf, &result, sizeof(result));
	memcpy(send_buf + sizeof(result), &errno, sizeof(int));
	int sd = Send(sessfd, send_buf, sizeof(result) + sizeof(int), 0);
}

/* 
 * read_func - operation function when input call is "read".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void read_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameters from receive buffer
	int fd = *((int *) rcv_buf) - FD_OFFSET;
	size_t count = *((size_t *) (rcv_buf + sizeof(int)));
	free(rcv_buf);
	
	//call read
	char *read_buf = Malloc(count * sizeof(char));
	ssize_t result = read(fd, read_buf, count);

	int send_size = 0;
	// if read success, send back return value, errno and read buffer content
	if (result > 0) {
		send_size = sizeof(ssize_t) + sizeof(int) + result;
	} else { // if read failed, no need to send back read buffer
		send_size = sizeof(ssize_t) + sizeof(int);
	}
	char *send_buf = Malloc(send_size);
	memcpy(send_buf, &result, sizeof(ssize_t));
	memcpy(send_buf + sizeof(ssize_t), &errno, sizeof(int));
	if (result > 0) {
		memcpy(send_buf + sizeof(ssize_t) + sizeof(int), read_buf, result);
	}
	int sd = Send(sessfd, send_buf, send_size, 0); //send back to client
	free(read_buf);
	free(send_buf);
}

/* 
 * lseek_func - operation function when input call is "lseek".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void lseek_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameter from receive buffer
	int fd = *((int *) rcv_buf) - FD_OFFSET;
	off_t offset = *((off_t *) (rcv_buf + sizeof(int)));
	int whence = *((int *) (rcv_buf + sizeof(int) + sizeof(off_t)));
	free(rcv_buf);

	//call lseek
	off_t result = lseek(fd, offset, whence);

	//send back return value and errno
	char send_buf[sizeof(off_t) + sizeof(int)];
	memcpy(send_buf, &result, sizeof(off_t));
	memcpy(send_buf + sizeof(off_t), &errno, sizeof(int));
	int sd = Send(sessfd, send_buf, sizeof(off_t) + sizeof(int), 0);
}

/* 
 * unlink_func - operation function when input call is "unlink".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void unlink_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameter from receive buffer
	char *pathname = Malloc(msg_len);
	memcpy(pathname, rcv_buf, msg_len);
	free(rcv_buf);

	//call unlink
	int result = unlink(pathname);
	free(pathname);

	//send back return value and errno
	char send_buf[2 * sizeof(int)];
	memcpy(send_buf, &result, sizeof(int));
	memcpy(send_buf + sizeof(int), &errno, sizeof(int));
	int sd = Send(sessfd, send_buf, 2 * sizeof(int), 0);
}

/* 
 * stat_func - operation function when input call is "stat".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void stat_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameter from receive buffer
	int ver = *((int *) rcv_buf);
	int path_len = msg_len - sizeof(int);
	char *path = Malloc(path_len * sizeof(char));
	memcpy(path, rcv_buf + sizeof(int), path_len);
	free(rcv_buf);
	
	//call __xstat
	struct stat *stat_buf = Malloc(sizeof(struct stat));
	int result = __xstat(ver, path, stat_buf);
	free(path); 

	//send back return value, errno, stat_buf content
	char *send_buf = Malloc(2 * sizeof(int) + sizeof(struct stat));
	memcpy(send_buf, &result, sizeof(int));
	memcpy(send_buf + sizeof(int), &errno, sizeof(int));
	memcpy(send_buf + sizeof(int) + sizeof(int), stat_buf, sizeof(struct stat));
	int sd = Send(sessfd, send_buf, 2 * sizeof(int) + sizeof(struct stat), 0);
	free(stat_buf); free(send_buf);
}

/* 
 * getdirentries_func - operation function when input call is "getdirentries".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void getdirentries_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameter from receive buffer
	int fd = *((int *) rcv_buf) - FD_OFFSET;
	size_t nbytes = *((size_t *) (rcv_buf + sizeof(int)));
	off_t *basep = (off_t *) (rcv_buf + sizeof(int) + sizeof(size_t));
	char *getdir_buf = Malloc(nbytes * sizeof(char));
	free(rcv_buf);

	//call getdirentries
	ssize_t result = getdirentries(fd, getdir_buf, nbytes, basep);

	//send back: return value, errno, besep content, getdirentries buffer content
	size_t send_len = sizeof(ssize_t) + sizeof(int) + nbytes + sizeof(off_t);
	char *send_buf = Malloc(send_len * sizeof(char));
	memcpy(send_buf, &result, sizeof(ssize_t));
	memcpy(send_buf + sizeof(ssize_t), &errno, sizeof(int));
	memcpy(send_buf + sizeof(ssize_t) + sizeof(int), basep, sizeof(off_t));
	memcpy(send_buf + sizeof(ssize_t) + sizeof(int) + sizeof(off_t), getdir_buf, nbytes);
	int sd = Send(sessfd, send_buf, send_len, 0);
	free(getdir_buf);
	free(send_buf);
}

/* 
 * getdirtree_func - operation function when input call is "getdirtree".
 * args: int sessfd, 
 *       int msg_len: the length of massage to be received next
 * return: void
 */
void getdirtree_func(int sessfd, int msg_len) {
	char *rcv_buf = Malloc(msg_len);
	int rv = Recv(sessfd, rcv_buf, msg_len, 0); //receive from client

	//get input parameter from receive buffer
	char *path = Malloc(msg_len);
	memcpy(path, rcv_buf, msg_len);
	free(rcv_buf);
	
	//call getdirtree
	struct dirtreenode *root = getdirtree(path);
	free(path);
	size_t *len = Malloc(sizeof(size_t));
	*len = 0;
	char *serial = serialize(root, len); //serialize dirtree to string
	freedirtree(root);

	//send back: serialize string length, errno, serialize string
	size_t serial_len = *len;
	size_t send_size = sizeof(size_t) + sizeof(int) + serial_len;
	char *send_buf = Malloc(send_size);
	memcpy(send_buf, len, sizeof(size_t));
	memcpy(send_buf + sizeof(size_t), &errno, sizeof(int));
	memcpy(send_buf + sizeof(size_t) + sizeof(int), serial, serial_len);
	int sd = Send(sessfd, send_buf, send_size, 0); //send to client
	free(len);
	free(serial);
	free(send_buf);
}

int main(int argc, char**argv) {
	char buf[MAXMSGLEN];
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=35797;

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);
	
	// main server loop, handle clients one at a time, quit after 10 clients
	while (1) {
		
		// wait for next client, get session socket
		sa_size = sizeof(struct sockaddr_in);
		sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (sessfd<0) err(1,0);

		//fork a child
		int fk = fork();
		//reap zombie children using signal handler
		if (fk != 0) {
			if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
				perror(0);
				exit(1);
			}
		}
		//child process
		if (fk == 0) {
			close(sockfd);
			// receive call head and msg_len from client
			while ( (rv=recv(sessfd, buf, HEAD_LEN + sizeof(int), 0)) > 0) {
				// get operation call
				int call_len = strlen(buf) + 1;
				char *input_call = Malloc(call_len * sizeof(char));
				memcpy(input_call, buf, call_len);
				printf("%s\n", input_call);

				// get length of massage to be received next
				int *msg_len = Malloc(sizeof(int));
				memcpy(msg_len, buf + HEAD_LEN, sizeof(int));
				
				// based on operation call, choose different functions
				if (!strcmp(input_call, "open")) {
					open_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "close")) {
					close_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "write")) {
					write_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "read")) {
					read_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "lseek")) {
					lseek_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "unlink")) {
					unlink_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "stat")) {
					stat_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "getdirentries")) {
					getdirentries_func(sessfd, *msg_len);
				} else if (!strcmp(input_call, "getdirtree")) {
					getdirtree_func(sessfd, *msg_len);
				}
				free(msg_len);
				free(input_call);
			}
			close(sessfd);
			exit(0);
		}
		close(sessfd);
	}
	// close socket
	close(sockfd);
	return 0;
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
			exit(1);
			break;
		}
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
			exit(1);
			break;
		}
		len -= rvnum;
		tmp += rvnum;
	}
	return len;
}


