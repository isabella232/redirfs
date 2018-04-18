/*
 *          Copyright Frantisek Hrbata 2008 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 *
 * Modified work:
 * Copyright 2015 Cisco Systems, Inc.
 *
 */

#ifndef __AV_H__
#define __AV_H__

#include <sys/types.h>

#define AV_EVENT_OPEN  1
#define AV_EVENT_CLOSE 2
#define AV_EVENT_RENAME_TO 3

#define AV_ACCESS_ALLOW 1
#define AV_ACCESS_DENY  2

#define AV_CACHE_DISABLE 0
#define AV_CACHE_ENABLE  1

#define AV_DEV_PATH "/dev/ampavflt"

struct av_connection {
	int fd;
};

/* For open and close events, the file will be open and so the file descriptor
 * field "fd" will be populated.  However, the "path" field will not be
 * populated and will be set to NULL.  av_get_filename() can be called to
 * obtain the path if desired.
 *
 * For rename events, the file will not be open so the file descriptor field
 * "fd" will be set to -1.  However, the "path" field will be populated with
 * the rename operation's destination path.  This path could reference a file
 * or a directory.
 */
struct av_event {
	int id;
	int type;
	int fd;
	pid_t pid;
	pid_t tgid;
	pid_t ppid;
	uid_t ruid;
	int res;
	int cache;
	char *path;
};

int av_register(struct av_connection *conn);
int av_unregister(struct av_connection *conn);
int av_register_trusted(struct av_connection *conn);
int av_unregister_trusted(struct av_connection *conn);
int av_request(struct av_connection *conn, struct av_event *event, int timeout);
int av_reply(struct av_connection *conn, struct av_event *event);
int av_set_result(struct av_event *event, int res);
int av_set_cache(struct av_event *event, int cache);
int av_get_filename(struct av_event *event, char *buf, int size);

#endif

