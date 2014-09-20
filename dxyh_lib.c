#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include "dxyh.h"
#include "error.h"		/* error handles */

static struct flock lock_it, unlock_it;
static int lock_fd = -1;


/*
 * functions as follows are so called packet-functions.
 * You can add more for further use.
 */

int Socket(int family, int type, int protocol)
{
	int		n;
	
	if (-1 == (n = socket(family, type, protocol)))
		err_sys_q("socket error");
	return n;
}

void Socketpair(int family, int type, int protocol, int *fd)
{
	int		n;

	if ((n = socketpair(family, type, protocol, fd)) < 0)
		err_sys_q("socketpair error");
}

int Bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	int n;

	if (-1 == (n = bind(sockfd, my_addr, addrlen)))
		err_sys_q("bind error");
	return n;
}

int Listen(int socket, int backlog)
{
	char *ptr = NULL;
	int n;

	if ((ptr = getenv("LISTENQ")) != NULL)
		backlog = atoi(ptr);

	if (-1 == (n = listen(socket, backlog)))
		err_sys_q("listen error");
	return n;
}

int Accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int n;

	if (-1 == (n = accept(s, addr, addrlen)))
		err_sys_q("accept error");
	return n;
}

/*
 * read n bytes
 */
ssize_t readn(int fd, void *buf, size_t n)
{
	size_t bytestoread;
	ssize_t bytesread;
	char *ptr = NULL;

	for (ptr = buf, bytestoread = n;
		 bytestoread > 0;
		 ptr += bytesread, bytestoread -= bytesread) {
		if ((bytesread = read(fd, ptr, bytestoread)) < 0) {
			if (EINTR == errno)
				bytesread = 0;
			else
				return -1;
		} else if (0 == bytesread)
			break;
	}
	return (n - bytestoread);
}

ssize_t Readn(int fd, void *buf, size_t n)
{
	ssize_t		len;

	if (-1 == (len = readn(fd, buf, n)))
		err_sys_q("readn error");
	return len;
}
	
ssize_t Read(int fd, void *buf, size_t len)
{
	ssize_t		n;

	if (-1 == (n = read(fd, buf, len)))
		err_sys_q("read error");
	return n;
}

/*
 * write n bytes
 */
ssize_t writen(int fd, const void *buf, size_t n)
{
	size_t bytestowrite;
	ssize_t byteswritten;
	const char *ptr = NULL;

	for (ptr = buf, bytestowrite = n;
		bytestowrite > 0;
		ptr += byteswritten, bytestowrite -= byteswritten) {
		byteswritten = write(fd, ptr, bytestowrite);
			/* an error occurred */
		if (-1 == byteswritten && errno != EINTR)
			return -1;
			/* interrupted by signal SIGINT, continue to write */
		if (-1 == byteswritten)
			byteswritten = 0;
	}
	return n;
}

ssize_t Writen(int fd, const void *buf, size_t n)
{
	ssize_t		len;

	if (-1 == (len = writen(fd, buf, n)))
		err_sys_q("writen error");
	return len;
}

ssize_t Write(int fd, const void *buf, size_t len)
{
	ssize_t		n;

	if (-1 == (n = write(fd, buf, len)))
		err_sys_q("write error");
	return n;
}

int Close(int fildes)
{
	int n;

	if (-1 == (n = close(fildes)))
		err_sys_q("close error");
	return n;
}

const char *Inet_ntop(int af, const void *src, char *dst,
		socklen_t size)
{
	const char *ptr = NULL;

	if (NULL == src)
		err_msg_q("NULL 3rd argument to inet_ntop");
	if (NULL == (ptr = inet_ntop(af, src, dst, size)))
		err_sys_q("inet_ntop error");
	return ptr;
}

int Inet_pton(int af, const char *src, void *dst)
{
	int n;

	if (-1 == (n = inet_pton(af, src, dst)))
		err_sys_q("inet_pton error");
	else if (0 == n)
		err_msg_q("inet_pton error for %s", src);
	return n;
}

in_addr_t Inet_addr(const char *cp)
{
	in_addr_t	s_addr;

	if ((in_addr_t) -1 == (s_addr = inet_addr(cp)))
		err_msg_q("inet_addr error");
	return s_addr;
}

char *Inet_ntoa(struct in_addr in)
{
	return inet_ntoa(in);
}

int Connect(int socket, const struct sockaddr *address,
		socklen_t address_len)
{
	int n;

	if (-1 == (n = connect(socket, address, address_len)))
		err_sys_q("connect error");
	return n;
}

/*
 * read 1 byte form fd with buffering
 */
ssize_t Read1(int fd, char *ptr)
{
	static int read_cnt = 0;
	static char *read_ptr = NULL;
	static char read_buf[MAXLINE];

	if (read_cnt <= 0) {
		again:
		if (-1 == (read_cnt = read(fd, read_buf,
						sizeof(read_buf)))) {
			if (EINTR == errno)
				goto again;
			return -1;
		}
		else if (0 == read_cnt)
			return 0;
		read_ptr = read_buf;
	}
	--read_cnt;
	*ptr = *read_ptr++;
	return 1;
}

/*
 * read one line form fd
 */
ssize_t Readline(int fd, void *vptr, size_t maxlen)
{
	ssize_t n, rc;
	char c, *ptr = vptr;

	for (n = 1; n < maxlen; ++n) {
		again:
		if (1 == (rc = Read1(fd, &c))) {
			*ptr++ = c;
			if ('\n' == c)
				break;
		}
		else if (0 == rc) {
			if (1 == n)
				return 0;
			else
				break;
		}
		else {
			if (EINTR == errno)
				goto again;
			return (-1);
		}
	}
	*ptr = '\0';
	return n;
}

pid_t Fork(void)
{
	pid_t pid;

	if (-1 == (pid = fork()))
		err_sys_q("fork error");
	return pid;
}

char *Fgets(char *ptr, int n, FILE *stream)
{
	char *rptr = NULL;

	if (NULL == (rptr = fgets(ptr, n, stream)) && ferror(stream))
		err_sys_q("fgets error");
	return rptr;
}

void Fputs(const char *ptr, FILE *stream)
{
	if (EOF == fputs(ptr, stream))
		err_sys_q("fputs error");
}

void *Calloc(size_t n, size_t size)
{
	void *ptr;

	if (NULL == (ptr = calloc(n, size)))
		err_sys_q("calloc error");
	return ptr;
}

void Dup2(int fd1, int fd2)
{
	if (-1 == dup2(fd1, fd2))
		err_sys_q("dup2 error");
}

void Gettimeofday(struct timeval *tv, void *foo)
{
	if (-1 == gettimeofday(tv, foo))
		err_sys_q("gettimeofday error");
}

int Ioctl(int fd, int request, void *arg)
{
	int		n;

	if (-1 == (n = ioctl(fd, request, arg)))
		err_sys_q("ioctl error");
	return n;
}

int Open(const char *pathname, int oflag, mode_t mode)
{
	int		fd;

	if (-1 == (fd = open(pathname, oflag, mode)))
		err_sys_q("open error");
	return fd;
}

void Unlink(const char *pathname)
{
	if (-1 == unlink(pathname))
		err_sys_q("unlink error");
}

pid_t Wait(int *iptr)
{
	pid_t	pid;

	if (-1 == (pid = wait(iptr)))
		err_sys_q("wait error");
	return pid;
}

pid_t Waitpid(pid_t pid, int *iptr, int options)
{
	pid_t	retpid;

	if (-1 == (pid = waitpid(retpid, iptr, options)))
		err_sys_q("waitpid error");
	return retpid;
}

FILE *Fopen(const char *filename, const char *mode)
{
	FILE *fp;

	if (NULL == (fp = fopen(filename, mode)))
		err_sys_q("fopen error");
	return fp;
}

void Fclose(FILE *fp)
{
	if (fclose(fp) != 0)
		err_sys_q("fclose error");
}

Sigfunc *Signal(int signo, Sigfunc *func)
{
	Sigfunc *sigfunc;

	if (SIG_ERR == (sigfunc = signal(signo, func)))
		err_sys_q("signal error");
	return sigfunc;
}

pid_t Vfork(void)
{
	pid_t	pid;

	if (-1 == (pid = vfork()))
		err_sys_q("vfork error");
	return pid;
}

void Kill(pid_t pid, int sig)
{
	if (-1 == kill(pid, sig))
		err_sys_q("kill error");
}

FILE *Popen(const char *command, const char *mode)
{
	FILE	*fp;

	if (NULL == (fp = popen(command, mode)))
		err_sys_q("popen error");
	return fp;
}

void Pclose(FILE *stream)
{
	if (-1 == pclose(stream))
		err_sys_q("pclose error");
}

int Select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
	int n;

	if (-1 == (n = select(nfds, readfds, writefds, exceptfds, timeout)))
		err_sys_q("select error");
	return n;
}

char *sock_ntop(const struct sockaddr *sa, socklen_t salen)
{
	char		portstr[7];
	static char	str[128];

	switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *) sa;
			Inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str));
			if (ntohs(sin->sin_port) != 0) {
				snprintf(portstr, sizeof(portstr), ":%d",
						ntohs(sin->sin_port));
				strcat(str, portstr);
			}
			return str;
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			Inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str));
			if (ntohs(sin6->sin6_port) != 0) {
				snprintf(portstr, sizeof(portstr), ".%d",
						ntohs(sin6->sin6_port));
				strcat(str, portstr);
			}
			return str;
		} break;
		default:
			snprintf(str, sizeof(str),
					"sock_ntop error: unknown AF_xxx: %d, len %d",
					sa->sa_family, salen);
			return str;
	}
	return NULL;
}

char *Sock_ntop(const struct sockaddr *sa, socklen_t salen)
{
	char	*ptr = NULL;

	if (NULL == (ptr = sock_ntop(sa, salen)))
		err_sys_q("sock_ntop error");
	return ptr;
}

int Fcntl(int fd, int cmd, int arg)
{
	int		n;

	if (-1 == (n = fcntl(fd, cmd, arg)))
		err_sys_q("fcntl error");
	return n;
}

int connect_nonb(int sockfd, const SA *saptr,
		socklen_t salen, int nsec)
{
	int			flags;
	socklen_t	len, n, error;
	fd_set		rset, wset;
	struct timeval tv;

	flags = Fcntl(sockfd, F_GETFL, 0);
	Fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if (-1 == (n = connect(sockfd, saptr, salen)))
		if (errno != EINPROGRESS)
			return -1;

	if (0 == n)
		goto done;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tv.tv_sec = nsec;
	tv.tv_usec = 0;
	if (0 == (n = Select(sockfd+1, &rset, &wset, NULL,
					nsec ? &tv : NULL))) {
		Close(sockfd);
		errno = ETIMEDOUT;
		return -1;
	}
	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (-1 == getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
					&error, &len))
			return -1;
	} else
		err_msg_q("select error: sockfd not set");

done:
	Fcntl(sockfd, F_SETFL, flags);
	if (error) {
		Close(sockfd);
		errno = error;
		return -1;
	}
	return 0;
}

void Shutdown(int fd, int how)
{
	if (-1 == shutdown(fd, how))
		err_sys_q("shutdown error");
}

int tcp_listen(const char *host, const char *serv,
		socklen_t *addrlenp)
{
	int		listenfd, n;
	const int	on = 1;
	struct addrinfo hints, *res = NULL, *ressave = res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_msg_q("tcp_listen error for %s, %s: %s",
				host, serv, gai_strerror(n));
	ressave = res;
	do {
		listenfd = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);
		if (-1 == listenfd)
			continue;

		Setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (0 == bind(listenfd, res->ai_addr, res->ai_addrlen))
			break;
		Close(listenfd);
	} while ((res = res->ai_next) != NULL);

	if (NULL == res)
		err_msg_q("tcp_listen error for %s, %s", host, serv);

	Listen(listenfd, LISTENQ);

	if (addrlenp)
		*addrlenp = res->ai_addrlen;

	freeaddrinfo(ressave);
	return listenfd;
}

int Tcp_listen(const char *host, const char *serv,
		socklen_t *addrlenp)
{
	return (tcp_listen(host, serv, addrlenp));
}

struct addrinfo *host_serv(const char *host, const char *serv,
		int family, int socktype)
{
	int		n;
	struct addrinfo hints, *res = NULL;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = family;
	hints.ai_socktype = socktype;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return NULL;
	return res;
}

int tcp_connect(const char *host, const char *serv)
{
	int		sockfd, n;
	struct addrinfo hints, *res = NULL, *ressave = res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_msg_q("tcp_connect error for %s, %s: %s",
				host, serv, gai_strerror(n));
	ressave = res;
	do {
		sockfd = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);
		if (-1 == sockfd)
			continue;

		if (0 == connect(sockfd, res->ai_addr, res->ai_addrlen))
			break;

		Close(sockfd);
	} while ((res = res->ai_next) != NULL);

	if (NULL == res)
		err_sys_q("tcp_connect error for %s, %s", host, serv);

	freeaddrinfo(ressave);
	return sockfd;
}

int Tcp_connect(const char *host, const char *serv)
{
	return (tcp_connect(host, serv));
}

void Setsockopt(int fd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	if (-1 == setsockopt(fd, level, optname, optval, optlen))
		err_sys_q("setsockopt error");
}

void Getpeername(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
	if (-1 == getpeername(fd, sa, salenptr))
		err_sys_q("getpeername error");
}

void Getsockname(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
	if (-1 == getsockname(fd, sa, salenptr))
		err_sys_q("getsockname error");
}

void *Malloc(size_t size)
{
	void *ptr = NULL;

	if (NULL == (ptr = malloc(size)))
		err_sys_q("malloc error");
	return ptr;
}

char *Getcwd(char *buf, size_t size)
{
	char	*ptr;

	if (NULL == (ptr = getcwd(buf, size)))
		err_sys_q("getcwd error");
	return ptr;
}

void Mkdir(const char *path, mode_t mode)
{
	if (-1 == mkdir(path, mode))
		err_sys_q("mkdir error");
}

void Rmdir(const char *path)
{
	if (-1 == rmdir(path))
		err_sys_q("rmdir error");
}

void Chdir(const char *path)
{
	if (-1 == chdir(path))
		err_sys_q("Chdir error");
}

DIR *Opendir(const char *dirname)
{
	DIR		*dirp;

	if (NULL == (dirp = opendir(dirname)))
		err_sys_q("Opendir error");
	return dirp;
}

void Closedir(DIR *dirp)
{
	if (-1 == closedir(dirp))
		err_sys_q("closedir error");
}

void Mkstemp(char *template)
{
	if (-1 == mkstemp(template) || 0 == template[0])
		err_msg_q("mkstemp error");
}

void my_lock_init(char *pathname)
{
	char	lock_file[1024];

	strncpy(lock_file, pathname, sizeof(lock_file));
	Mkstemp(lock_file);

	lock_fd = Open(lock_file, O_CREAT | O_WRONLY, FILE_MODE);
	Unlink(lock_file);

	lock_it.l_type = F_WRLCK;
	lock_it.l_whence = SEEK_SET;
	lock_it.l_start = 0;
	lock_it.l_len = 0;

	unlock_it.l_type = F_UNLCK;
	unlock_it.l_whence = SEEK_SET;
	unlock_it.l_start = 0;
	unlock_it.l_len = 0;
}

void my_lock_wait(void)
{
	int		rc;

	while ((rc = fcntl(lock_fd, F_SETLKW, &lock_it)) < 0) {
		if (EINTR == errno)
			continue;
		else
			err_sys_q("fcntl error for my_lock_wait");
	}
}

void my_lock_release(void)
{
	if (fcntl(lock_fd, F_SETLKW, &unlock_it) < 0)
		err_sys_q("fcntl error for my_lock_release");
}

void *Mmap(void *addr, size_t len, int prot, int flags, 
		int fd, off_t offset)
{
	void	*ptr;

	if ((void *) -1 == (ptr = mmap(addr, len, prot, flags, fd, offset)))
		err_sys_q("mmap error");
	return ptr;
}

