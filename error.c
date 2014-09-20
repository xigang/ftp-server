#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include "error.h"
#include "dxyh_thread.h"
#include "record.h"
#include "dxyh.h"

static void err_handle(int errnoflg, int thread_err_code,
		const char *fmt, va_list ap);

/*
 * err_sys -- print system error msg
 */
void err_sys(const char *cause, ...)
{
	va_list ap;

	va_start(ap, cause);
	err_handle(1, 0, cause, ap);
	va_end(ap);
	return;
} /* end err_sys */

/*
 * err_msg -- print normal err msg
 */
void err_msg(const char *cause, ...)
{
	va_list ap;

	va_start(ap, cause);
	err_handle(0, 0, cause, ap);
	va_end(ap);
	return;
}  /* end err_msg */

/*
 * t_err_sys -- thread print system error msg, the quit
 */
void t_err_sys(int thread_err_code, const char *cause, ...)
{
	va_list ap;

	va_start(ap, cause);
	err_handle(2, thread_err_code, cause, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
} /* end t_err_sys */

/*
 * err_handle -- error handle function
 * @errnoflg: if none zero will show sys err, otherwise not
 * @thread_err_code: error code in thread
 * @fmt: err string format wants printing
 * @ap: handle arguments
 */
static void err_handle(int errnoflg, int thread_err_code,
			const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLINE];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	n = strlen(buf);
		/*If want to show system error msg*/
	if (1 == errnoflg) {
		/*Save errno, because 'strerror' may modify it*/
		errno_save = errno;
		snprintf(buf+n, sizeof(buf)-n,
				": %s", strerror(errno_save));
	}
	else if (2 == errnoflg)
		snprintf(buf+n,
				sizeof(buf)-n,": %s",strerror(thread_err_code));
	strcat(buf, "\n");

		/*Output the final error msg*/
	fflush(stdout); /*In case stdout and stderr are the same*/
	my_lock_mutex_wait();
	fputs(buf, stderr);
	my_lock_mutex_release();
	fflush(stderr);
	return ;
} /* end err_handle */
