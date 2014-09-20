#include <stdio.h>
#include "ftpd.h"
#include "record.h"
#include "error.h"
#include "dxyh.h"

int main(int argc, char **argv)
{
	int		listenfd;

	ftpd_init();
	ftpd_parse_args(argc, argv);
	listenfd = ftpd_create_serv();
	ftpd_do_loop(listenfd);
	return 0;
}

