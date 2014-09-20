#ifndef _ERROR_H_
#define _ERROR_H_

#include <errno.h>

extern int errno;

#ifndef MAXLINE
#define MAXLINE 1024
#endif

extern void err_sys(const char *cause, ...);
#define err_sys_q(cause, ...) \
	do { \
		err_sys(cause, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while (0)

extern void err_msg(const char *cause, ...);
#define err_msg_q(cause, ...) \
	do { \
		err_msg(cause, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while (0)

extern void t_err_sys(int t_err_code, const char *cause, ...);

#endif /* _ERROR_H_ */
