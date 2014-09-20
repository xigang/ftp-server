#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "dxyh.h"
#include "dxyh_thread.h"
#include "ftpd.h"
#include "error.h"
#include "record.h"

extern log_t *logfd;

static void ftpd_usage(void);
static void ftpd_verbose(void);
static void ftpd_help(void);
static void ftpd_sig_chld(int signo);
static void ftpd_sig_int(int signo);
static void ftpd_chld_sig_quit(int signo);
static int ftpd_ctrl_conn_handler(int ctrlfd);
static const char *ftpd_serv_resp_num2msg(int num);
int ftpd_send_resp(int ctrlfd, int num, ...);
static int ftpd_do_request(int ctrlfd, char *buff);
static int ftpd_do_auth(int ctrlfd, char *cmd);
static int ftpd_do_user(int ctrlfd, char *cmd);
static int ftpd_do_pass(int ctrlfd, char *cmd);
static int ftpd_do_pwd(int ctrlfd, char *cmd);
static int ftpd_do_cwd(int ctrlfd, char *cmd);
static int ftpd_do_list(int ctrlfd, char *cmd);
static int ftpd_do_syst(int ctrlfd, char *cmd);
static int ftpd_do_size(int ctrlfd, char *cmd);
static int ftpd_do_dele(int ctrlfd, char *cmd);
static int ftpd_do_rmd(int ctrlfd, char *cmd);
static int ftpd_do_retr(int ctrlfd, char *cmd);
static int ftpd_do_stor(int ctrlfd, char *cmd);
static int ftpd_do_pasv(int ctrlfd, char *cmd);
static int ftpd_do_nlst(int ctrlfd, char *cmd);
static int ftpd_do_port(int ctrlfd, char *cmd);
static int ftpd_do_type(int ctrlfd, char *cmd);
static int ftpd_do_quit(int ctrlfd, char *cmd);
static int ftpd_do_mkd(int ctrlfd, char *cmd);
static int ftpd_get_port_mode_ipport(char *cmd,
		in_addr_t *ip, uint16_t *port);
static int ftpd_get_connfd(void);
static int ftpd_get_list_stuff(char buff[], size_t len);
static int get_file_info(const char *filename,
		char buff[], size_t len);
static int dir_path_ok(const char *dir_path);
static void ftpd_close_all_fds(void);
static void parent_atlast(void);
static void pr_cpu_time(void);
static void ptransfer(const char *direction, long bytes,
		const struct timeval *t0,
		const struct timeval *t1);
static int add2pids(pid_t pid);
static void dele_from_pids(pid_t pid);

int			ftpd_debug_on;
int			ftpd_record_on;
int			ftpd_quit_flag;
int			ftpd_hash_print;
int			ftpd_tick_print;
uint16_t	ftpd_serv_port; 
char		ftpd_cur_dir[PATH_MAX];
int			ftpd_cur_pasv_fd;
int			ftpd_cur_pasv_connfd;
int			ftpd_cur_port_fd;
int			ftpd_cur_type;
const struct ftpd_user_st *ftpd_cur_user;
int			ftpd_nchild;
pid_t		pids[MAX_CHIHLD_NUM];

const struct ftpd_cmd_st ftpd_cmds[] = {
	{ "AUTH", ftpd_do_auth },
	{ "USER", ftpd_do_user },
	{ "PASS", ftpd_do_pass },
	{ "PWD",  ftpd_do_pwd  },
	{ "XPWD", ftpd_do_pwd  },
	{ "CWD",  ftpd_do_cwd  },
	{ "LIST", ftpd_do_list },
	{ "MKD",  ftpd_do_mkd  },
	{ "XMKD", ftpd_do_mkd  },
	{ "SYST", ftpd_do_syst },
	{ "SIZE", ftpd_do_size },
	{ "DELE", ftpd_do_dele },
	{ "RMD",  ftpd_do_rmd  },
	{ "TYPE", ftpd_do_type },
	{ "RETR", ftpd_do_retr },
	{ "STOR", ftpd_do_stor },
	{ "NLST", ftpd_do_nlst },
	{ "PASV", ftpd_do_pasv },
	{ "PORT", ftpd_do_port },
	{ "QUIT", ftpd_do_quit },
	{ NULL, NULL },
};

const struct ftpd_user_st ftpd_users[] = {
	{ "anonymous", "" },
	{ "ftp", "" },
	{ "dengxiayehu", "123456" }
};

const char ftpd_serv_resps[][256] = {
	"150 %s" FTPD_LINE_END,
	"200 %s" FTPD_LINE_END,
	"213 Size of \"%s\" is %ld." FTPD_LINE_END,
	"215 Linux Type." FTPD_LINE_END,
	"220 Ftpd" FTPD_VER " ready for new user." FTPD_LINE_END,
	"221 Goodbye." FTPD_LINE_END,
	"226 %s" FTPD_LINE_END,
	"227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)." FTPD_LINE_END,
	"230 Login successful." FTPD_LINE_END,
	"250 Directory successfully changed." FTPD_LINE_END,
	"257 %s" FTPD_LINE_END,
	"331 %s" FTPD_LINE_END,
	"350 %s" FTPD_LINE_END,
	"500 %s" FTPD_LINE_END,
	"530 %s" FTPD_LINE_END,
	"550 %s" FTPD_LINE_END
};

/*
 * show msg in debug mode
 */
void ftpd_debug(const char *file, int line,
		const char *fmt, ...)
{
	if (ftpd_debug_on) {
		va_list		ap;
		int		off = 0;
		char	buff[MAXLINE];

		off = snprintf(buff, sizeof(buff), "(%s:%d:%ld) ",
				file, line, (long) getpid());
			/* for security, you should prefer vsprintf to vsnprintf */
		va_start(ap, fmt);
		vsnprintf(buff + off, sizeof(buff) - off, fmt, ap);
		va_end(ap);
			/* make sure the print won't be disturbed */
		my_lock_mutex_wait();
		fprintf(stderr, buff);
		my_lock_mutex_release();
	}
}

/*
 * initialization, add parent-process's init stuff here
 */
void ftpd_init(void)
{
	int		i;

	ftpd_debug_on = OFF;		/* default is OFF*/
	ftpd_record_on = OFF;
	ftpd_hash_print = OFF;
	ftpd_tick_print = OFF;
	ftpd_quit_flag = 0;
	ftpd_serv_port = SERV_PORT;	/* defiend in dxyh.h, 9877 as def */
	ftpd_cur_port_fd = -1;		/* port sockfd */
	ftpd_cur_pasv_fd = -1;		/* passive sockfd */
	ftpd_cur_pasv_connfd = -1;
	ftpd_cur_type = TYPE_A;
	pids[0] = getpid();
	for (i = 1; i < MAX_CHIHLD_NUM; ++i)
		pids[i] = -1;
	ftpd_nchild = 0;
	Signal(SIGPIPE, SIG_IGN);	/* ignore signal SIG_INT */
	Signal(SIGCHLD, ftpd_sig_chld);	/* install other signals' handler */
	Signal(SIGINT, ftpd_sig_int);
	my_lock_mutex_init();		/* initialize the mutex-lock */
	atexit(parent_atlast);		/* show something or do some cleanup */
}

/*
 * handle the args
 *
 * -d/--debug --> open debug mode
 * -p/--port [port#] --> specify the listen port (9877 as default)
 * -r/--record["filenam"] --> open log mode ("logfile.txt" as default)
 * -h/--help --> show help
 * -v/--verbose --> show version
 *
 * @argc:
 * @argv: the args passed to main func
 */
void ftpd_parse_args(int argc, char **argv)
{
	int		do_verbose, do_help;
	int		err_flg;
	char	c, log_filename[PATH_MAX];
	struct option longopts[] = {
		{ "port", required_argument, NULL, 'p' },
		{ "debug", no_argument, NULL, 'd' },
		{ "record", optional_argument, NULL, 'r' },
		{ "verbose", no_argument, &do_verbose, 1 },
		{ "help", no_argument, &do_help, 1 },
		{ 0, 0, 0, 0 }
	};

	do_verbose = OFF;
	do_help = OFF;
	err_flg = 0;
	while ((c = getopt_long(argc, argv, ":hr::vp:dW;", longopts, NULL)) != -1) {
		switch (c) {
			case 'd':
				ftpd_debug_on = ON;
				ftpd_hash_print = ON;	/* show '#' within transfer */
				ftpd_tick_print = ON;	/* try it, you will know */
				break;
			case 'r':
				strcpy(log_filename, optarg ? optarg : FTPD_DEF_LOGFILE);
				ftpd_record_on = ON;
				break;
			case 'v':
				do_verbose = ON;
				break;
			case 'h':
				do_help = ON;
				break;
			case 'p':
				if (0 == (ftpd_serv_port = (uint16_t) atoi(optarg)))
					err_flg = 1;
				break;
			case 0:
				break;
			case ':':
				err_msg("%s: option `-%c' requires an argument",
						argv[0], optopt);
				err_flg = 1;
				break;
			case '?':
			default:
				err_msg("%s: %c: unknow option", argv[0], optopt);
				err_flg = 1;
				break;
		}
	}

	if (err_flg) {
		ftpd_usage();
		exit(EXIT_FAILURE);
	} else if (do_help) {
		ftpd_help();
		exit(EXIT_SUCCESS);
	}
	else if (do_verbose) {
		ftpd_verbose();
		exit(EXIT_SUCCESS);
	}

	if (ftpd_record_on) {
		if (NULL == (logfd = log_open(log_filename, LOG_DEFAULT))) {
			FTPD_DEBUG("Cannot open logfile \"%s\"", log_filename);
			exit(EXIT_FAILURE);
		}
		FTPD_DEBUG_LOG(INFO, "Prepare to log in \"%s\" ok.\n",
				log_filename);
	}
	
	FTPD_DEBUG("serv port %u\n", ftpd_serv_port);
}

/*
 * show usage when an error occurs
 */
static void ftpd_usage(void)
{
	printf("usage: ftpd_main [-p <port#>] [-r[\"filenam\"]][-v] [-d] [-h]\n");
}

/*
 * show version
 */
static void ftpd_verbose(void)
{
	printf("A simple ftp server.\n"
		   "It can support some of the mostly used cmds.\n"
		   "Author: Xigang Wang\n"
		   "Mail: wangxigang2014@gmail.com\n"
		   "Ftpd version: 1.1\n");
}

/*
 * show help
 */
static void ftpd_help(void)
{
	printf("You can use any ftp client software to login.\n"
		   "Cmds as follows are supported:\n"
		   "user ls cd pwd get mget delete put mput\n"
		   "size port passive ascii binary dir mkdir\n"
		   "......\n"
		   "Well, you can add more cmds!\n");
}

/*
 * parent process create a listen fd
 */
int ftpd_create_serv(void)
{
	int		listenfd;
	const int	on = 1;
	struct sockaddr_in servaddr;

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	Setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(ftpd_serv_port);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));

	Listen(listenfd, LISTENQ);

	FTPD_DEBUG_LOG(INFO, "create serv-listenfd ok %s\n",
			Sock_ntop((SA *) &servaddr, sizeof(servaddr)));
	return listenfd;
}

/*
 * main loop, server is always listening and fork a child to handle
 * the new client
 */
int ftpd_do_loop(int listenfd)
{
	int		ctrlfd;
	pid_t	childpid;

	for ( ; ; ) {
		FTPD_DEBUG("server is ready for a new  connection ...\n");
		if (-1 == (ctrlfd = accept(listenfd, NULL, NULL))) {
			FTPD_DEBUG_LOG(ERROR, "accept failed: %s\n",
					strerror(errno));
			continue;
		}

		if (ftpd_debug_on) {	/* get client's info */
			struct sockaddr_in	clitaddr;
			socklen_t	clitlen;
			Getpeername(ctrlfd, (SA *) &clitaddr, &clitlen);
			FTPD_DEBUG("accept a connection from %s:%u\n",
					Inet_ntoa(clitaddr.sin_addr),
					ntohs(clitaddr.sin_port));
		}

		if (-1 == (childpid = fork())) { /* fork a child to handle */
			FTPD_DEBUG_LOG(ERROR, "fork failed: %s\n", strerror(errno));
			Close(ctrlfd);
			continue;
		} else if (0 == childpid) {
			Close(listenfd);
			Signal(SIGCHLD, SIG_IGN);
			Signal(SIGINT, SIG_IGN);
			Signal(SIGQUIT, ftpd_chld_sig_quit);
			Chdir("/");		/* default directory is / */
			Getcwd(ftpd_cur_dir, sizeof(ftpd_cur_dir));
			if (ftpd_ctrl_conn_handler(ctrlfd) != FTPD_OK)
				_exit(EXIT_FAILURE);
			_exit(EXIT_SUCCESS);
		}
		add2pids(childpid);	/* add child's pid to child-pid-array */
		Close(ctrlfd);
	}
}

/*
 * parent's SIGCHLD handler
 */
static void ftpd_sig_chld(int signo)
{
	int		status;
	pid_t	pid;
		/* get the terminated child-process's status */
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status) && !WEXITSTATUS(status))
			FTPD_DEBUG("child %ld terminated normally\n", (long) pid);
		else if (WIFEXITED(status))
			FTPD_DEBUG("child %ld terminated with code %d\n",
					(long) pid, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			FTPD_DEBUG("child %ld terminated due to signal %d\n",
					(long) pid, WTERMSIG(status));
		else if (WIFSTOPPED(status))
			FTPD_DEBUG("child %ld stopped due to signal %d\n",
					(long) pid, WSTOPSIG(status));
	}	/* close child's fds such as pasvfd portfd ... */
	dele_from_pids(pid);
	pr_cpu_time();	/* show some more useful info */
}

/*
 * print the time of system running
 */
static void pr_cpu_time(void)
{
	double	user, sys;
	struct rusage	myusage, childusage;

	if (getrusage(RUSAGE_SELF, &myusage) < 0)
		err_sys_q("getrusage error");

	if (getrusage(RUSAGE_CHILDREN, &childusage) < 0)
		err_sys_q("getrusage error");

	user = (double) myusage.ru_utime.tv_sec +
		myusage.ru_utime.tv_usec/1000000.0;
	user += (double) childusage.ru_utime.tv_sec +
		childusage.ru_utime.tv_usec/1000000.0;
	sys = (double) myusage.ru_stime.tv_sec +
		myusage.ru_stime.tv_usec/1000000.0;
	sys += (double) childusage.ru_stime.tv_sec +
		childusage.ru_stime.tv_usec/1000000.0;
	FTPD_DEBUG_LOG(INFO, "user time = %g, sys time = %g\n",
			user, sys);
}

/*
 * parent's SIGINT handler
 */
static void ftpd_sig_int(int signo)
{
	int		i;
	FTPD_DEBUG_LOG(ERROR, "ftpd interrupted by signal SIGINT!\n");
	for (i = 1; i < ftpd_nchild + 1; ++i)	/* kill children all */
		if (pids[i] != -1)
			Kill(pids[i], SIGQUIT);
	exit(EXIT_FAILURE);
}

/*
 * child's SIGQUIT handler
 */
static void ftpd_chld_sig_quit(int signo)
{
	ftpd_close_all_fds();
	_exit(EXIT_FAILURE);
}

static int add2pids(pid_t pid)
{
	int		i;

	for (i = 1; i < MAX_CHIHLD_NUM; ++i)
		if (-1 == pids[i]) {
			pids[i] = pid;
			++ftpd_nchild;
			return FTPD_OK;
		}
	return FTPD_ERR;
}

static void dele_from_pids(pid_t pid)
{
	int		i;

	for (i = 1; i < MAX_CHIHLD_NUM; ++i)
		if (pids[i] == pid) {
			pids[i] = -1;
			--ftpd_nchild;
			break;
		}
}

static const char *ftpd_serv_resp_num2msg(int num)
{
	int		index;
	char	buff[4];

	snprintf(buff, sizeof(buff), "%d", num);
	if (strlen(buff) != 3)
		return NULL;

	for (index = 0; index < FTPD_ARR_LEN(ftpd_serv_resps); ++index)
		if (0 == strncmp(buff, ftpd_serv_resps[index], 3))
			return ftpd_serv_resps[index];
	return NULL;
}

/*
 * send the response to client ftp software
 */
int ftpd_send_resp(int ctrlfd, int num, ...)
{
	const char	*cp = ftpd_serv_resp_num2msg(num);
	va_list		ap;
	char		line[MAXLINE];

	if (NULL == cp) {
		FTPD_DEBUG("ftpd_serv_resp_num2msg(%d)failed\n", num);
		return FTPD_ERR;
	}

	va_start(ap, num);
	vsnprintf(line, sizeof(line), cp, ap);
	va_end(ap);
	FTPD_DEBUG("send resp: %s", line);
	Writen(ctrlfd, line, strlen(line));	/* better use Writen than Write */
	return FTPD_OK;
}

/*
 * handle cmds
 */
static int ftpd_do_request(int ctrlfd, char *buff)
{
	char	*end = &buff[strlen(buff) - 1];
	char	*space = strchr(buff, ' ');
	char	save;
	int		i;

	if ('\n' == *end && '\r' == *(end - 1)) {
			/* this is a valid ftp request */
		*(buff + strlen(buff) - 2) = '\0';	/* drop '\r' & '\n' */
		if (NULL == space)
			space = &buff[strlen(buff)];
		save = *space;
		*space = '\0';
		for (i = 0; ftpd_cmds[i].cmd != NULL; ++i) { /* check cmd */
			if (0 == strcmp(buff, ftpd_cmds[i].cmd)) {
				*space = save;
				FTPD_DEBUG("received a valid cmd %s\n", buff);
					/* call certain cmd's certain handler */
				return ftpd_cmds[i].cmd_handler(ctrlfd, buff);
			}
		}

		*space = save;
		FTPD_DEBUG_LOG(ERROR, "received a unsupported ftp cmd: %s\n", buff);
		*space = '\0';
		ftpd_send_resp(ctrlfd, 500, "Unsupported cmd.");
		return FTPD_ERR;
	}
	FTPD_DEBUG("received a invalid ftp cmd\n");
	ftpd_send_resp(ctrlfd, 500, "Invalid cmd.");
	return FTPD_ERR;
}

static int ftpd_ctrl_conn_handler(int ctrlfd)
{
	char	line[MAXLINE];
	ssize_t	n;

	/*
	 * Control connection has set up,
	 * we can send out the first ftp msg.
	 */
	if (ftpd_send_resp(ctrlfd, 220) != FTPD_OK) {
		Close(ctrlfd);
		FTPD_DEBUG("close the ctrl connection ok\n");
		return FTPD_ERR;
	}

	for ( ; ; ) {
		if (0 == (n = Read(ctrlfd, line, sizeof(line)))) {
			FTPD_DEBUG_LOG(INFO, "client closed the connection\n");
			break;
		}
		line[n] = '\0';
		FTPD_DEBUG("Got cmd = %s", line);
		if (ftpd_do_request(ctrlfd, line) != FTPD_OK)
			FTPD_DEBUG_LOG(ERROR, "something may be wrong during handling\n");
		if (ftpd_quit_flag) break;
	}
	Close(ctrlfd);
	ftpd_close_all_fds();
	FTPD_DEBUG_LOG(INFO, "client exits normally\n");
	return FTPD_OK;
}

/*
 * handle AUTH, not immpleted
 */
static int ftpd_do_auth(int ctrlfd, char *cmd)
{
	return ftpd_send_resp(ctrlfd, 530,
			"Please login with USER and PASS.");
}

/*
 * USER
 */
static int ftpd_do_user(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');

	if (space) {
		int		i;
		for (i = 0; i < FTPD_ARR_LEN(ftpd_users); ++i)
			if (0 == strcmp(space + 1, ftpd_users[i].user)) {
				FTPD_DEBUG("certain user(%s) is found\n", space + 1);
				ftpd_cur_user = &ftpd_users[i];
				break;
			}
		if (NULL == ftpd_cur_user) {
			FTPD_DEBUG("user(%s) is not found\n", space + 1);
			ftpd_send_resp(ctrlfd, 550, "User is not found.");
			return FTPD_ERR;
		}
		return ftpd_send_resp(ctrlfd, 331,
				"Please sepcify the password.");
	}
	ftpd_send_resp(ctrlfd, 550, "Username blank.");
	return FTPD_ERR;
}

/*
 * PASS
 */
static int ftpd_do_pass(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');

	if (ftpd_cur_user != NULL && space != NULL) {
		if ('\0' == ftpd_cur_user->pass[0] ||
			  0  == strcmp(space + 1, ftpd_cur_user->pass)) {
			FTPD_DEBUG("password for %s ok\n", ftpd_cur_user->user);
			return ftpd_send_resp(ctrlfd, 230);
		}
		FTPD_DEBUG("password for %s error\n", ftpd_cur_user->user);
	}
	ftpd_cur_user = NULL;
	ftpd_send_resp(ctrlfd, 530, "Login incorrect.");
	return FTPD_ERR;
}

/*
 * PWD
 */
static int ftpd_do_pwd(int ctrlfd, char *cmd)
{
	FTPD_CHECK_LOGIN();
	Getcwd(ftpd_cur_dir, sizeof(ftpd_cur_dir));
	return ftpd_send_resp(ctrlfd, 257, ftpd_cur_dir);
}

/*
 * CWD
 */
static int ftpd_do_cwd(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	char	cur_dir[PATH_MAX], line[MAXLINE];

	FTPD_CHECK_LOGIN();

	if (NULL == space) {
		snprintf(line, sizeof(line), "Missing dest dir-path.");
		goto err_ret;
	}

	if (-1 == chdir(space + 1)) {
		snprintf(line, sizeof(line), "Invalid dest dir-path.");
		goto err_ret;
	}

	FTPD_DEBUG("dest dir-path is: %s\n", space + 1);
	Getcwd(cur_dir, sizeof(cur_dir));
	return ftpd_send_resp(ctrlfd, 250);
err_ret:
	ftpd_send_resp(ctrlfd, 550, line);
	return FTPD_ERR;
}

static int ftpd_get_connfd(void)
{
	int		sockfd;

	if (ftpd_cur_pasv_fd >= 0) {
		sockfd = accept(ftpd_cur_pasv_fd, NULL, NULL);
		if (sockfd != -1) {
			Close(ftpd_cur_pasv_fd);
			ftpd_cur_pasv_fd = -1;
			ftpd_cur_pasv_connfd = sockfd;
			return sockfd;
		} else
			FTPD_DEBUG("accept error: %s\n", strerror(errno));
	} else if (ftpd_cur_pasv_connfd >= 0) /* if available, use it */
		return ftpd_cur_pasv_connfd;
	return -1;
}

/*
 * for list or nlst
 */
static int get_file_info(const char *filename, char buff[], size_t len)
{
	char	mode[] = "----------";
	char	timebuf[MAXLINE];
	int		timelen, off = 0;
	struct passwd *pwd;
	struct group *grp;
	struct tm *ptm;
	struct stat st;

	if (-1 == stat(filename, &st)) {
		FTPD_DEBUG("stat error: %s\n", strerror(errno));
		return FTPD_ERR;
	}

	if (S_ISDIR(st.st_mode))
		mode[0] = 'd';
	if (st.st_mode & S_IRUSR)
		mode[1] = 'r';
	if (st.st_mode & S_IWUSR)
		mode[2] = 'w';
	if (st.st_mode & S_IXUSR)
		mode[3] = 'x';
	if (st.st_mode & S_IRGRP)
		mode[4] = 'r';
	if (st.st_mode & S_IWGRP)
		mode[5] = 'w';
	if (st.st_mode & S_IXGRP)
		mode[6] = 'x';
	if (st.st_mode & S_IROTH)
		mode[7] = 'r';
	if (st.st_mode & S_IWOTH)
		mode[8] = 'w';
	if (st.st_mode & S_IXOTH)
		mode[9] = 'x';
	mode[10] = '\0';
	off += snprintf(buff + off, len - off, "%s", mode);
	off += snprintf(buff + off, len - off, "%2d", 1);

	if (NULL == (pwd = getpwuid(st.st_uid))) {
		FTPD_DEBUG("getpwuid error: %s\n", strerror(errno));
		return FTPD_ERR;
	}
	off += snprintf(buff + off, len - off, " %4s", pwd->pw_name);

	if (NULL == (grp = getgrgid(st.st_gid))) {
		FTPD_DEBUG("getgrgid error: %s\n", strerror(errno));
		return FTPD_ERR;
	}
	off += snprintf(buff + off, len - off, " %4s",
			(char *) grp->gr_name);

	off += snprintf(buff + off, len - off, " %*d", 8,
			(int) st.st_size);

	ptm = localtime(&st.st_mtime);
	if (ptm != NULL
	&& (timelen = strftime(timebuf, sizeof(timebuf), " %b %d %H:%S", ptm)) > 0) {
		timebuf[timelen] = '\0';
		off += snprintf(buff + off, len - off, "%s", timebuf);
	} else {
		FTPD_DEBUG("localtime error: %s\n", strerror(errno));
		return FTPD_ERR;
	}
	off += snprintf(buff + off, len - off, " %s\r\n", filename);
	return off;
}

static int ftpd_get_list_stuff(char buff[], size_t len)
{
	DIR		*dir;
	struct dirent *dent;
	int		off = 0;
	char	*filename;

	dir = Opendir(".");
	buff[0] = '\0';
	while ((dent = readdir(dir)) != NULL) {
		filename = dent->d_name;
		if ('.' == filename[0])
			continue;
		off += get_file_info(filename, buff + off, len - off);
	}
	return off;
}

/*
 * LIST, ethier file or directory
 */
static int ftpd_do_list(int ctrlfd, char *cmd)
{
	int		sockfd, n;
	char	buff[BUFSIZ];
	char	line[MAXLINE];
	char	tmp_dir_path[PATH_MAX];
	char	*space = strchr(cmd, ' ');
	
	FTPD_CHECK_LOGIN();

	if (-1 == (sockfd = ftpd_get_connfd())) {
		FTPD_DEBUG("LIST cmd: no available sockfd\n");
		snprintf(line, sizeof(line), "List transport refused.");
		goto err_ret;
	}

	ftpd_send_resp(ctrlfd, 150, "Here comes the directory listing.");

	if (space) {
		if (!dir_path_ok(space + 1)) { /* maybe a file, check it */
			struct stat	st;
			if (-1 == stat(space + 1, &st) && ENOENT == errno) {
					/* file not exists */
				FTPD_DEBUG("LIST cmd: file \"%s\"not exists\n",
						space + 1);
				snprintf(line, sizeof(line),
						"File \"%s\" specified not exists.", space + 1);
				goto err_ret;
			}
				/* actually a file */
			n = get_file_info(space + 1, buff, sizeof(buff));
			goto ok_ret;
		}
		Getcwd(tmp_dir_path, sizeof(tmp_dir_path));
		Chdir(space + 1);
	}
	n = ftpd_get_list_stuff(buff, sizeof(buff));
	if (space)
		Chdir(tmp_dir_path);
ok_ret:
	if (n >= 0)
		Writen(sockfd, buff, n);
	else {
		FTPD_DEBUG("ftpd_get_list_stuff failed\n");
		snprintf(line, sizeof(line), "List directory failed.");
		goto err_ret;
	}
	ftpd_close_all_fds();
	return ftpd_send_resp(ctrlfd, 226, "Directory send OK.");
err_ret:
	ftpd_close_all_fds();
	ftpd_send_resp(ctrlfd, 550, line);
	return FTPD_ERR;
}

/*
 * NLST
 */
static int ftpd_do_nlst(int ctrlfd, char *cmd)
{
	int		sockfd;
	char	*space = strchr(cmd, ' ');
	char	line[MAXLINE], filename[PATH_MAX];
	struct stat st;

	FTPD_CHECK_LOGIN();

	if (-1 == (sockfd = ftpd_get_connfd())) {
		FTPD_DEBUG("NLST cmd: no available sockfd\n");
		snprintf(line, sizeof(line), "File transport refused.");
		goto err_ret;
	}

	ftpd_send_resp(ctrlfd, 150, "Begin to do nlst.");

	if (space) {
		if (dir_path_ok(space + 1)) { /* directory wouldn't transferd */
			FTPD_DEBUG("NLST cmd error: \"%s\" is directory\n",
					space + 1);
			snprintf(line, sizeof(line), "Cannot transfer directory.");
			goto err_ret;
		}
			/* check file whether exists */
		if (-1 == stat(space + 1, &st) && ENOENT == errno) {
			FTPD_DEBUG("NLST cmd error: \"%s\" not exists\n", space + 1);
			snprintf(line, sizeof(line), "File specified not exists.");
			goto err_ret;
		}
		snprintf(filename, sizeof(filename), "%s\r\n", space + 1);
	} else {
		FTPD_DEBUG("NLST cmd error: missing filename\n");
		snprintf(line, sizeof(line), "File not specified.");
		goto err_ret;
	}

	Writen(sockfd, filename, strlen(filename));
	ftpd_close_all_fds();
	return ftpd_send_resp(ctrlfd, 226, "Do nlst done.");
err_ret:
	ftpd_close_all_fds();
	return ftpd_send_resp(ctrlfd, 500, line);
}


static void ftpd_close_all_fds(void)
{
	if (ftpd_cur_pasv_fd >= 0) {
		Close(ftpd_cur_pasv_fd);
		ftpd_cur_pasv_fd = -1;
	}

	if (ftpd_cur_pasv_connfd >= 0) {
		Close(ftpd_cur_pasv_connfd);
		ftpd_cur_pasv_connfd = -1;
	}

	if (ftpd_cur_port_fd >= 0) {
		Close(ftpd_cur_port_fd);
		ftpd_cur_port_fd = -1;
	}
}

/*
 * check the directory whether exists
 */
static int dir_path_ok(const char *dir_path)
{
	DIR		*dir;

	if (NULL == (dir = opendir(dir_path)))
		return 0;
	Closedir(dir);
	return 1;
}

/*
 * SYST
 */
static int ftpd_do_syst(int ctrlfd, char *cmd)
{
	FTPD_CHECK_LOGIN();
	return ftpd_send_resp(ctrlfd, 215);
}

/*
 * SIZE
 */
static int ftpd_do_size(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	struct	stat	st;

	FTPD_CHECK_LOGIN();
	if (NULL == space || -1 == lstat(space + 1, &st)) {
		FTPD_DEBUG("SIZE cmd error: %s: %s\n", cmd, strerror(errno));
		ftpd_send_resp(ctrlfd, 550, "Could not get the file's size.");
		return FTPD_ERR;
	}
	return ftpd_send_resp(ctrlfd, 213, space + 1, (long) st.st_size);
}

/*
 * delete, caution!
 */
static int ftpd_do_dele(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	struct	stat	st;

	FTPD_CHECK_LOGIN();
	if (NULL == space ||
	 	-1 == lstat(space + 1, &st) ||
	 	-1 == remove(space + 1)) {
	 	FTPD_DEBUG("DELE cmd error: %s: %s\n", cmd, strerror(errno));
	 	ftpd_send_resp(ctrlfd, 550, "Delete file failed.");
		return FTPD_ERR;
	}
	return ftpd_send_resp(ctrlfd, 200, "Delete file successfully.");
}

/*
 * create a passive sockfd waitting for connection
 */
static int ftpd_do_pasv(int ctrlfd, char *cmd)
{
	socklen_t	pasvlen;
	struct sockaddr_in pasvaddr;
	uint16_t	port;
	in_addr_t	ip;

	FTPD_CHECK_LOGIN();

	if (ftpd_cur_pasv_fd >= 0) {
		Close(ftpd_cur_pasv_fd);
		ftpd_cur_pasv_fd = -1;
	}

	ftpd_cur_pasv_fd = Socket(AF_INET, SOCK_STREAM, 0);
	pasvlen = sizeof(pasvaddr);
	Getsockname(ctrlfd, (SA *) &pasvaddr, &pasvlen);
	pasvaddr.sin_port = htons(0);	/* let system choose the port */
	Bind(ftpd_cur_pasv_fd, (SA *) &pasvaddr, sizeof(pasvaddr));

	Listen(ftpd_cur_pasv_fd, LISTENQ);

	pasvlen = sizeof(pasvaddr);
	Getsockname(ftpd_cur_pasv_fd, (SA *) &pasvaddr, &pasvlen);
	ip = ntohl(pasvaddr.sin_addr.s_addr);
	port = ntohs(pasvaddr.sin_port);
	FTPD_DEBUG_LOG(INFO, "local bind: %s: %u\n",
			Inet_ntoa(pasvaddr.sin_addr), port);

	return ftpd_send_resp(ctrlfd, 227, (ip >> 24) & 0xff,
			(ip >> 16) & 0xff, (ip >> 8) & 0xff,
			ip & 0xff, (port >> 8) & 0xff, port & 0xff);
}

static int ftpd_get_port_mode_ipport(char *cmd,
		in_addr_t *ip, uint16_t *port)
{
	char	*cp = strchr(cmd, ' ');
	int		i;
	unsigned char buff[6];

	if (NULL == cp)
		return FTPD_ERR;

	for (++cp, i = 0; i < FTPD_ARR_LEN(buff); ++cp, ++i) {
		buff[i] = atoi(cp);
		cp = strchr(cp, ',');
		if (NULL == cp && i < FTPD_ARR_LEN(buff) - 1)
			return FTPD_ERR;
	}

	if (ip) *ip = *(in_addr_t *) &buff[0];
	if (port) *port = *(uint16_t *) &buff[4];
	return FTPD_OK;
}

/*
 * create a sockfd to connect to client
 */
static int ftpd_do_port(int ctrlfd, char *cmd)
{
	in_addr_t	ip;
	uint16_t	port;
	struct sockaddr_in servaddr;

	FTPD_CHECK_LOGIN();

	if (ftpd_cur_port_fd >= 0) {
		Close(ftpd_cur_port_fd);
		ftpd_cur_port_fd = -1;
	}

	ftpd_cur_port_fd = Socket(AF_INET, SOCK_STREAM, 0);

	if (ftpd_get_port_mode_ipport(cmd, &ip, &port) != FTPD_OK) {
		FTPD_DEBUG_LOG(ERROR, "ftpd_get_port_mode_ipport error");
		Close(ftpd_cur_port_fd);
		ftpd_cur_port_fd = -1;
		ftpd_send_resp(ctrlfd, 550, "Port failed.");
		return FTPD_ERR;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = port;
	servaddr.sin_addr.s_addr = ip;
	FTPD_DEBUG_LOG(INFO, "PORT cmd: %s: %u\n",
			Inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));

	Connect(ftpd_cur_port_fd, (SA *) &servaddr, sizeof(servaddr));

	FTPD_DEBUG("PORT mode connect ok\n");
	return ftpd_send_resp(ctrlfd, 200, "Port command OK.");
}

/*
 * make a directory
 */
static int ftpd_do_mkd(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	char	line[MAXLINE];

	if (space) {
		FTPD_CHECK_LOGIN();
		if (dir_path_ok(space + 1)) {
			FTPD_DEBUG("directory %s already exists\n", space + 1);
			snprintf(line, sizeof(line), "Directory already exists.");
			goto err_ret;
		} else if (-1 == mkdir(space + 1, 0777)) {
			snprintf(line, sizeof(line), "Create specified direcotry failed.");
			goto err_ret;
		}
		snprintf(line, sizeof(line), "Directory \"%s\" created.",
				space + 1);
		return ftpd_send_resp(ctrlfd, 257, line);
	}
	snprintf(line, sizeof(line), "Missing directory name.");
err_ret:
	ftpd_send_resp(ctrlfd, 550, line);
	return FTPD_ERR;
}

/*
 * remove a directory
 */
static int ftpd_do_rmd(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	char	line[MAXLINE];

	if (space) {
		FTPD_CHECK_LOGIN();
		if (!dir_path_ok(space + 1)) {
			FTPD_DEBUG("directory %s not found\n", space + 1);
			snprintf(line, sizeof(line), "Directory \"%s\" is not exists.",
					space + 1);
			goto err_ret;
		} else if (-1 == rmdir(space + 1)) {
			FTPD_DEBUG("rmdir \"%s\" error:%s\n",
					space + 1, strerror(errno));
			snprintf(line, sizeof(line), "Remove specified directory failed.");
			goto err_ret;
		}
		snprintf(line, sizeof(line), "Directory \"%s\" removed.",
				space + 1);
		return ftpd_send_resp(ctrlfd, 257, line);
	}
	snprintf(line, sizeof(line), "Missing directory name.");
err_ret:
	ftpd_send_resp(ctrlfd, 550, line);
	return FTPD_ERR;
}

/*
 * set ethier ASCII mode or BINARY mode
 */
static int ftpd_do_type(int ctrlfd, char *cmd)
{
	char	*space = strchr(cmd, ' ');
	char	line[MAXLINE];

	 if (space != NULL) {
	 	FTPD_CHECK_LOGIN();
	 	if ('I' == *(space + 1))
	 		ftpd_cur_type = TYPE_I;
	 	else if ('A' == *(space + 1))
	 		ftpd_cur_type = TYPE_A;
	 	else {
			snprintf(line, sizeof(line), "Type mode unknown.");
			goto err_ret;
		}
	 	snprintf(line, sizeof(line), "Switching to %s mode.",
	 			ftpd_cur_type ? "Binary" : "ASCII");
	 	return ftpd_send_resp(ctrlfd, 200, line);
	 }
	 snprintf(line, sizeof(line), "Missing type mode.");
err_ret:
	 ftpd_send_resp(ctrlfd, 500, line);
	 return FTPD_ERR;
}

/*
 * show some info of the transfer
 */
static void ptransfer(const char *direction, long bytes,
		const struct timeval *t0,
		const struct timeval *t1)
{
	if (ftpd_debug_on) {
		struct timeval td;
		float s, bs;

		td.tv_sec  = t1->tv_sec  - t0->tv_sec;
		td.tv_usec = t1->tv_usec - t0->tv_usec;
		if (td.tv_usec < 0)
			td.tv_sec--, td.tv_usec += 1000000;

		s = (float) td.tv_sec + (td.tv_usec/1000000.0);
		bs = bytes / (s == 0 ? 1 : s);
		printf("%ld bytes %s in %.3g secs(%.2g Kbytes/s)\n",
				bytes, direction, s, bs/1024.0);
	}
}

/*
 * send a file to client
 */
static int ftpd_do_retr(int ctrlfd, char *cmd)
{
	char	buff[BUFSIZ];
	char	*space = strchr(cmd, ' ');
	struct	stat	st;
	int		connfd;
	volatile long bytes, hashbytes;
	struct timeval start, stop;

	FTPD_CHECK_LOGIN();

	if (NULL == space) {
		FTPD_DEBUG("RETR cmd error: %s\n", cmd);
		goto err_ret;
	} else if (-1 == lstat(space + 1, &st)) {
		if ((space = strchr(space + 1, ' ')) != NULL) {
			space = strrchr(cmd, ' ');
			if (-1 == lstat(space + 1, &st)) {
				FTPD_DEBUG("RETR cmd error: file \"%s\" not exists",
						space + 1);
				goto err_ret;
			}
		}
	}

	if (-1 == (connfd = ftpd_get_connfd())) {
		FTPD_DEBUG("ftpd_get_connfd error\n");
		goto err_ret;
	}

	ftpd_send_resp(ctrlfd, 150, "File status OK, about to transfer.");

	if (ftpd_debug_on)
		gettimeofday(&start, (struct timezone *) 0);
	bytes = 0;
	hashbytes = HASHBYTES;
	if (TYPE_I == ftpd_cur_type) {	/* BINARY mode */
		int		fd;
		volatile int n;
		fd = Open(space + 1, O_RDONLY, 0);

		for ( ; ; ) {
			if (0 == (n = Read(fd, buff, sizeof(buff))))
				break;
			bytes += n;
			if (ftpd_hash_print) {
				while (bytes >= hashbytes) {
					putchar('#');
					hashbytes += HASHBYTES;
				}
				fflush(stdout);
			}
			if (ftpd_tick_print && (bytes >= hashbytes)) {
				printf("\rBytes transferred: %ld", bytes);
				fflush(stdout);
				while (bytes >= hashbytes)
					hashbytes += TICKBYTES;
			}
			Writen(connfd, buff, n);
		}
		if (ftpd_hash_print && bytes > 0) {
			if (bytes < HASHBYTES)
				putchar('#');
			putchar('\n');
			fflush(stdout);
		}
		if (ftpd_tick_print) {
			printf("\rBytes transferred: %ld\n", bytes);
			fflush(stdout);
		}
		Close(fd);
	} else {		/* ASCII mode */
		char	tmpbuff[BUFSIZ];
		register int i, k;
		volatile int sz;
		FILE	*fp;
	   
		if (NULL == (fp = fopen(space + 1, "r"))) {
			FTPD_DEBUG("open file to read error: %s\n",
					strerror(errno));
			goto err_ret;
		}

		while ((sz = fread(tmpbuff, 1, sizeof(tmpbuff)/2, fp)) > 0) {
			for (i = k = 0; i < sz; ++i) {
				if ('\n' == tmpbuff[i]) {
					if (ftpd_hash_print) {
						while (bytes >= hashbytes) {
							putchar('#');
							hashbytes += HASHBYTES;
						}
						fflush(stdout);
					}
					if (ftpd_tick_print && (bytes >= hashbytes)) {
						printf("\rBytes transferred: %ld", bytes);
						fflush(stdout);
						while (bytes >= hashbytes)
							hashbytes += TICKBYTES;
					}
					bytes++;
					buff[k++] = '\r';
				}
				buff[k++] = tmpbuff[i];
				bytes++;
			}
			Writen(connfd, buff, k);
		}
		if (ftpd_hash_print && bytes > 0) {
			if (bytes < HASHBYTES)
				putchar('#');
			putchar('\n');
			fflush(stdout);
		}
		if (ftpd_tick_print) {
			printf("\rBytes transferred: %ld\n", bytes);
			fflush(stdout);
		}
		if (ferror(fp) != 0) {
			FTPD_DEBUG("WARNING! file \"%s\" sent abnormally: %s\n",
					space + 1, strerror(errno));
			goto err_ret;
		}
		////////////////////////////////////
		// so slow the below is
		////////////////////////////////////
		// while ((c = fgetc(fp)) != EOF) {
		// 	if ('\n' == c) {
		// 		c = '\r';
		// 		Writen(connfd, &c, 1);
		// 		c = '\n';
		// 	}
		// 	Writen(connfd, &c, 1);
		// }
		////////////////////////////////////
		Fclose(fp);
	}
	if (ftpd_debug_on) {
		gettimeofday(&stop, (struct timezone *) 0);
		if (bytes > 0)
			ptransfer("send", bytes, &start, &stop);
	}
	FTPD_DEBUG("RETR \"%s\" successfully\n", space + 1);
	ftpd_close_all_fds();
	return ftpd_send_resp(ctrlfd, 226, "Require file transferd OK.");
err_ret:
	if (ftpd_debug_on) {
		gettimeofday(&stop, (struct timezone *) 0);
		if (bytes > 0)
			ptransfer("send", bytes, &start, &stop);
	}
	ftpd_send_resp(ctrlfd, 550, "File transferd error.");
	ftpd_close_all_fds();
	return FTPD_ERR;
}

/*
 * get a file form client ftp
 */
static int ftpd_do_stor(int ctrlfd, char *cmd)
{
	char	buff[BUFSIZ];
	char	*space = strchr(cmd, ' ');
	struct	stat	st;
	volatile long bytes, hashbytes;
	struct timeval start, stop;
	int		connfd;

	FTPD_CHECK_LOGIN();

	if (NULL == space || 0 == lstat(space + 1, &st)) {
		FTPD_DEBUG("STOR cmd error: %s\n", cmd);
		goto err_ret;
	}

	if (-1 == (connfd = ftpd_get_connfd())) {
		FTPD_DEBUG("ftpd_get_connfd error\n");
		goto err_ret;
	}

	ftpd_send_resp(ctrlfd, 150, "Ready to receive file.");
	if (ftpd_debug_on)
		gettimeofday(&start, (struct timezone *) 0);
	bytes = 0;
	hashbytes = HASHBYTES;
	if (TYPE_I == ftpd_cur_type) {
		int		fd;
		volatile int n;
		if (-1 == (fd = open(space + 1,
				O_WRONLY | O_CREAT | O_TRUNC, 0660))) {
			FTPD_DEBUG("open file to write error: %s\n",
					strerror(errno));
			goto err_ret;
		}
		for ( ; ; ) {
			if (0 == (n = Read(connfd, buff, sizeof(buff))))
				break;
			bytes += n;
			if (ftpd_hash_print) {
				while (bytes >= hashbytes) {
					putchar('#');
					hashbytes += HASHBYTES;
				}
				fflush(stdout);
			}
			if (ftpd_tick_print && (bytes >= hashbytes)) {
				printf("\rBytes transferred: %ld", bytes);
				fflush(stdout);
				while (bytes >= hashbytes)
					hashbytes += TICKBYTES;
			}
			Writen(fd, buff, n);
		}
		if (ftpd_hash_print && bytes > 0) {
			if (bytes < HASHBYTES)
				putchar('#');
			putchar('\n');
			fflush(stdout);
		}
		if (ftpd_tick_print) {
			printf("\rBytes transferred: %ld\n", bytes);
			fflush(stdout);
		}
		Close(fd);
	} else {
		char	c;
		volatile int lf_count = 0;
		FILE	*fp;
		if (NULL == (fp = Fopen(space + 1, "w"))) {
			FTPD_DEBUG("open file to write error: %s\n",
					strerror(errno));
			goto err_ret;
		}
		while (1 == Read1(connfd, &c)) {
			if ('\n' == c)
				++lf_count;
			while ('\r' == c) {
				++bytes;
				Read1(connfd, &c);
				if (c != '\n') {
					putc('\r', fp);
					if ('\0' == c) {
						++bytes;
						goto contin;
					}
					if (EOF == c)
						goto contin;
				}
			}
			putc(c, fp);
			++bytes;
contin:
			while (ftpd_hash_print && bytes >= hashbytes) {
				putchar('#');
				hashbytes += HASHBYTES;
			}
			fflush(stdout);
			if (ftpd_tick_print && bytes >= hashbytes) {
				printf("\rBytes received: %ld", bytes);
				fflush(stdout);
				while (bytes >= hashbytes)
					hashbytes += TICKBYTES;
			}
		}
		if (ftpd_hash_print && bytes > 0) {
			if (bytes < HASHBYTES)
				putchar('#');
			putchar('\n');
			fflush(stdout);
		}
		if (ftpd_tick_print) {
			printf("\rBytes received: %ld\n", bytes);
			fflush(stdout);
		}
		if (lf_count) {
			FTPD_DEBUG("WARNING! %d bare linefeeds received in ASCII mode.\n"
					"\tFile may not have transferred correctly.\n", lf_count);
		}
		if (ferror(fp) != 0) {
			FTPD_DEBUG("WARNING! file \"%s\" received abnormally: %s\n",
					space + 1, strerror(errno));
			goto err_ret;
		}
		Fclose(fp);
	}
	if (ftpd_debug_on) {
		gettimeofday(&stop, (struct timezone *) 0);
		if (bytes > 0)
			ptransfer("received", bytes, &start, &stop);
	}
	FTPD_DEBUG("STOR (%s) successfully\n", space + 1);
	ftpd_close_all_fds();
	sync();
	return ftpd_send_resp(ctrlfd, 226, "File received OK.");
err_ret:
	if (ftpd_debug_on) {
		gettimeofday(&stop, (struct timezone *) 0);
		if (bytes > 0)
			ptransfer("received", bytes, &start, &stop);
	}
	ftpd_send_resp(ctrlfd, 550, "File received error.");
	ftpd_close_all_fds();
	return FTPD_ERR;
}

static int ftpd_do_quit(int ctrlfd, char *cmd)
{
	FTPD_CHECK_LOGIN();
	ftpd_send_resp(ctrlfd, 221);
	ftpd_quit_flag = 1;
	return FTPD_OK;
}

static void parent_atlast(void)
{
	FTPD_DEBUG_LOG(INFO, "Server is shutdown!\n");
	if (ftpd_record_on)		/* close the log file if necessary */
		log_close(logfd);
}

