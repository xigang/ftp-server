#ifndef _DXYH_H
#define _DXYH_H

#include <unistd.h>		/* for ssize_t */
#include <netinet/in.h>	/* for sockaddr */
#include <dirent.h>		/* for DIR */

#define MAXLINE		1024
#define LISTENQ		1024
#define SERV_PORT	9877	/* server's default listen port */
#define MAXSOCKADDR	128

#define max(a, b)	((a) > (b) ? (a) : (b))
#define min(a, b)	((a) < (b) ? (a) : (b))

#define FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define DIR_MODE	(FILE_MODE | S_IXUSR | S_IXGRP | S_IXOTH)

typedef struct sockaddr	SA;/* for convenience */
typedef void Sigfunc(int);

int Socket(int family, int type, int protocol);
void Socketpair(int family, int type, int protocol, int *fd);
int Bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
int Listen(int socket, int backlog);
int Accept(int s, struct sockaddr *addr, socklen_t *addrlen);
ssize_t Read(int fd, void *buf, size_t len);
ssize_t Write(int fd, const void *buf, size_t len);
ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);
ssize_t Readn(int fd, void *buf, size_t n);
ssize_t Read1(int fd, char *ptr);
ssize_t Writen(int fd, const void *buf, size_t n);
int Close(int fildes);
const char *Inet_ntop(int af, const void *src, char *dst,
		socklen_t size);
int Inet_pton(int af, const char *src, void *dst);
in_addr_t Inet_addr(const char *cp);
char *Inet_ntoa(struct in_addr n);
int Connect(int socket, const struct sockaddr *address,
		socklen_t address_len);
ssize_t Readline(int fd, void *vptr, size_t maxlen);
pid_t Fork(void);
pid_t Vfork(void);
char *Fgets(char *ptr, int n, FILE *stream);
void Fputs(const char *ptr, FILE *stream);
void *Calloc(size_t n, size_t size);
void Dup2(int fd1, int fd2);
void Gettimeofday(struct timeval *tv, void *foo);
int Ioctl(int fd, int request, void *arg);
int Open(const char *pathname, int oflag, mode_t mode);
void Unlink(const char *pathname);
pid_t Wait(int *iptr);
pid_t Waitpid(pid_t pid, int *iptr, int options);
FILE *Fopen(const char *filename, const char *mode);
void Fclose(FILE *fp);
FILE *Popen(const char *command, const char *mode);
void Pclose(FILE *stream);
Sigfunc *Signal(int signo, Sigfunc *func);
void Kill(pid_t pid, int sig);
int Select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);
char *Sock_ntop(const struct sockaddr *sa, socklen_t salen);
struct addrinfo *host_serv(const char *host, const char *serv,
		int family, int socktype);
int Tcp_connect(const char *host, const char *serv);
void Getpeername(int fd, struct sockaddr *sa,
		socklen_t *salenptr);
void Getsockname(int fd, struct sockaddr *sa,
		socklen_t *salenptr);
void *Malloc(size_t size);
char *Getcwd(char *buf, size_t size);
void Chdir(const char *path);
void Mkdir(const char *path, mode_t mode);
void Rmdir(const char *path);
DIR *Opendir(const char *dirname);
void Closedir(DIR *dirp);
void Setsockopt(int fd, int level, int optname,
		const void *optval, socklen_t optlen);
int Tcp_listen(const char *host, const char *serv,
		socklen_t *addrlenp);
int Fcntl(int fd, int cmd, int arg);
void Shutdown(int fd, int how);
int connect_nonb(int sockfd, const SA *saptr,
		socklen_t salen, int nsec);
void Mkstemp(char *template);
void my_lock_init(char *pathname);
void my_lock_wait(void);
void my_lock_release(void);
void *Mmap(void *addr, size_t len, int prot, int flags, 
		int fd, off_t offset);
#endif

