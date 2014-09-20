#include <stdio.h>
#include <unistd.h>
#include <semaphore.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dxyh.h"
#include "dxyh_thread.h"
#include "record.h"
#include "error.h"

log_t	*logfd = NULL;

/*
 * lprintf -- record function, write to logfile
 * @log_t: returned from log_open
 * @level: DEBUG INFO WARN ERROR FATAL
 * @fmt: formatted string
 * return: succ - 0, fail - 1
 */
static int lprintf(log_t *log, unsigned int level, int err_flg, int t_err_code,
					const char *fmt, va_list ap);

log_t *log_open(const char *filename, int flags)
{
	log_t *log = NULL;
	
	if (NULL == (log = (log_t *) malloc(sizeof(log_t)))) {
		err_msg("log_open: Unable to malloc()");
		goto log_open_a;
	}

	log->flags = flags;
	log->fd = Open(filename, O_WRONLY | O_CREAT | O_NOCTTY |
				(flags & LOG_TRUNC ? O_TRUNC : O_APPEND), 0666);

	if (-1 == log->fd) {
		err_msg("log_open: open log file error");
		goto log_open_b;
	}

	if (-1 == sem_init(&log->sem, 0, 1)) {
		err_msg("log_open: Could not initialize log semaphore");
		goto log_open_c;
	}
	
	return log;
log_open_c:
	Close(log->fd);
log_open_b:
	free(log);
log_open_a:
	return NULL;
} /* end log_open */

void log_close(log_t *log)
{
	Sem_wait(&log->sem);
	Sem_destroy(&log->sem);
	Close(log->fd);
	free(log);
	return;
} /* end log_close */

void log_msg(log_t *log, unsigned int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	lprintf(log, level, 0, 0, fmt, ap);
	va_end(ap);
	return;
} /* end log_msg */

void log_sys(log_t *log, unsigned int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	lprintf(log, level, 1, 0, fmt, ap);
	va_end(ap);
	return;
} /* end log_sys */

void log_t_sys_q(log_t *log, unsigned int level, int t_err_code,
		const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	lprintf(log, level, 2, t_err_code, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
} /* end log_t_sys_q */

static int lprintf(log_t *log, unsigned int level, int err_flg,
		int t_err_code, const char *fmt, va_list ap)
{
	int fd;
	time_t now;
	char date[50];
	static char line[LOGLINE_MAX];
	static char processnum[10];
	int len;
	int errno_save;
	static char *levels[10] = {
		"[(bad)]", "[debug]", "[info]", "[warn]",
		"[error]", "[emerg]", "[fatal]"};

	if (NULL == log) return -1;

	fd = log->fd;
	if (!(log->flags&LOG_NODATE)) {
		now = time(NULL);
		strcpy(date, ctime(&now));
		date[strlen(date) - 6] = ' ';
		date[strlen(date) - 5] = '\0';
	}

	if (!(log->flags&LOG_NOPID))
		sprintf(processnum, "(PID:%ld) ", (long) getpid());

	snprintf(line, sizeof(line), "%s%s%s",
			log->flags&LOG_NODATE ? "" : date,
			log->flags&LOG_NOLVL ? "" : 
			(level > FATAL ? levels[0] : levels[level]),
			log->flags&LOG_NOPID ? "" : processnum);
	len = strlen(line);

	vsnprintf(line+len, sizeof(line) - len, fmt, ap);

	len = strlen(line);
	if (1 == err_flg) {
		errno_save = errno;
		snprintf(line+len, sizeof(line) - len,
				": %s", strerror(errno_save));
	}
	else if (2 == err_flg)
		snprintf(line+len, sizeof(line) - len,
				": %s", strerror(t_err_code));

	if (!(log->flags&LOG_NOLF))
		strcat(line, "\n");

	Sem_wait(&log->sem);
	Writen(fd, line, strlen(line));
	if (EMERG == level && (log->flags&LOG_STDERR))
		fprintf(stderr, "%s\n", line);
	Sem_post(&log->sem);

	return len;
} /* end lprintf */

