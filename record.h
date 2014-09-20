#ifndef _RECORD_H
#define _RECORD_H

#include <stdio.h>
#include <semaphore.h>

/* max record length */
#define LOGLINE_MAX 1024

/* record level */
#define DEBUG	1
#define INFO	2
#define WARN	3
#define ERROR	4
#define EMERG	5
#define FATAL	6

/* record type */
#define LOG_TRUNC	1<<0
#define LOG_NODATE	1<<1
#define LOG_NOLF	1<<2
#define LOG_NOLVL	1<<3
#define LOG_DEBUG	1<<4
#define LOG_STDERR	1<<5
#define LOG_NOPID	1<<6
#define LOG_DEFAULT	(LOG_STDERR | LOG_TRUNC | LOG_NOLF)

typedef struct log_t_tag {
	int fd;
	sem_t sem;
	int flags;
} log_t;

extern log_t *logfd;

/*
 * log_open -- open the log file
 * @filename: log filename
 * @flags: options for record
 *		LOG_DEFAULT -	show the most info
 *		LOG_TRUNC	-	drop opened log file
 *		LOG_NODATE	-	ignore the date
 *		LOG_NOLF	-	no new line for every record
 *		LOG_NOLVL	-	do not record the msg's level
 *		LOG_DEBUG	-	do not record msg
 *		LOG_STDERR	-	print on stderr
 *		LOG_NOPID	-	do not record the process #
 * return: succ - log_t(>0), fail - NULL
 */
log_t *log_open(const char *filename, int flags);

/*
 * log_close -- close the log file
 */
void log_close(log_t *log);

/*
 * use funcs below to write to logfile
 */
void log_msg(log_t *log, unsigned int level, const char *fmt, ...);
#define log_msg_q(log, level, fmt, ...)	\
	do { \
		log_msg(log, level, fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while (0)

void log_sys(log_t *log, unsigned int level, const char *fmt, ...);
#define log_sys_q(log, level, fmt, ...)	\
	do { \
		log_sys(log, level, fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while (0)

void log_t_sys_q(log_t *log, unsigned int level, int t_err_code,
		const char *fmt, ...);
#endif

