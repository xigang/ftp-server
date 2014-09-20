#ifndef _FTPD_H
#define _FTPD_H

#define FTPD_ARR_LEN(arr)		(sizeof(arr) / sizeof(arr[0]))
#define FTPD_VER				"1.0.1"
#define FTPD_DEF_SERV_PORT		21
#define FTPD_LINE_END			"\r\n"
#define FTPD_OK					0
#define FTPD_ERR				(-1)
#define FTPD_DEF_LOGFILE		"logfile.txt"
#define ON						1
#define OFF						0
#define TYPE_A					0
#define TYPE_I					1
#define HASHBYTES				1024
#define TICKBYTES				10240
#define MAX_CHIHLD_NUM			10

#define FTPD_CHECK_LOGIN()	\
	do { \
		if (NULL == ftpd_cur_user) {\
			ftpd_send_resp(ctrlfd, 530, "User haven't logged in"); \
			return FTPD_ERR; \
		}\
	} while (0)

#define FTPD_DEBUG(fmt, ...)	\
	ftpd_debug(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define FTPD_LOG(level, fmt, ...)	\
	do { \
		if (ftpd_record_on) \
			log_msg(logfd, level, fmt, ##__VA_ARGS__); \
	} while (0)

#define FTPD_DEBUG_LOG(level, fmt, ...) \
	do { \
		ftpd_debug(__FILE__, __LINE__, fmt, ##__VA_ARGS__); \
		if (ftpd_record_on) \
			log_msg(logfd, level, fmt, ##__VA_ARGS__); \
	} while (0)


struct ftpd_cmd_st {
	char	*cmd;
	int		(*cmd_handler)(int, char*);
};

struct ftpd_user_st {
	char	user[128];
	char	pass[128];
};

void ftpd_parse_args(int argc, char **argv);
void ftpd_debug(const char *file, int line,
		const char *fmt, ...);
void ftpd_init(void);
int ftpd_create_serv(void);
int ftpd_do_loop(int listenfd);
#endif

