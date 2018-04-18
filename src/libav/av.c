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

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <linux/limits.h>
#include "av.h"

static int av_open_conn(struct av_connection *conn, int flags)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if ((conn->fd = open(AV_DEV_PATH, flags)) == -1)
		return -1;

	return 0;
}

int av_register(struct av_connection *conn)
{
	return av_open_conn(conn, O_RDWR);
}

int av_unregister(struct av_connection *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if (close(conn->fd) == -1)
		return -1;

	return 0;
}

int av_register_trusted(struct av_connection *conn)
{
	return av_open_conn(conn, O_RDONLY);
}

int av_unregister_trusted(struct av_connection *conn)
{
	return av_unregister(conn);
}

int av_request(struct av_connection *conn, struct av_event *event, int timeout)
{
	static const char path_delim_str[] = ",path:";
	const size_t path_delim_len = sizeof(path_delim_str) - 1;
	struct timeval tv;
	struct timeval *ptv;
	char buf[256 + PATH_MAX];
	fd_set rfds;
	int rv = 0;
	char *p = NULL;

	if (!conn || !event || timeout < 0) {
		errno = EINVAL;
		return -1;
	}

	FD_ZERO(&rfds);
	FD_SET(conn->fd, &rfds);

	if (timeout) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout - (tv.tv_sec * 1000)) * 1000;
		ptv = &tv;
	} else
		ptv = NULL;

	while (!rv) {
		rv = select(conn->fd + 1, &rfds, NULL, NULL, ptv);
		if (rv == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (rv == -1)
			return -1;

		rv = read(conn->fd, buf, sizeof(buf));
		if (rv == -1)
			return -1;
	}

	/* Read the required parameters */
	if (sscanf(buf, "id:%d,type:%d,fd:%d,pid:%d,tgid:%d,ppid:%d,ruid:%d",
				&event->id, &event->type, &event->fd,
				&event->pid, &event->tgid, &event->ppid, &event->ruid) != 7)
		return -1;

	/* Read the optional path parameter.  If it exists, copy the path to a
	 * heap allocated buffer. */
	p = strstr(buf, path_delim_str);
	if (p) {
		p += path_delim_len;
		event->path = strdup(p);
		if (!event->path) {
			errno = ENOMEM;
			return -1;
		}
	} else {
		event->path = NULL;
	}

	event->res = 0;
	event->cache = AV_CACHE_ENABLE;

	return 0;
}

int av_reply(struct av_connection *conn, struct av_event *event)
{
	char buf[256];

	if (!conn || !event) {
		errno = EINVAL;
		return -1;
	}

	snprintf(buf, 256, "id:%d,res:%d,cache:%d", event->id, event->res,
			event->cache);

	if (write(conn->fd, buf, strlen(buf) + 1) == -1)
		return -1;

	if (event->fd >= 0) {
		if (close(event->fd) == -1)
			return -1;
	}

	event->fd = -1;

	free(event->path);
	event->path = NULL;

	return 0;
}

int av_set_result(struct av_event *event, int res)
{
	if (!event) {
		errno = EINVAL;
		return -1;
	}

	if (res != AV_ACCESS_ALLOW && res != AV_ACCESS_DENY) {
		errno = EINVAL;
		return -1;
	}

	event->res = res;

	return 0;
}

int av_set_cache(struct av_event *event, int cache)
{
	if (!event) {
		errno = EINVAL;
		return -1;
	}

	if (cache != AV_CACHE_ENABLE && cache != AV_CACHE_DISABLE) {
		errno = EINVAL;
		return -1;
	}

	event->cache = cache;

	return 0;
}

int av_get_filename(struct av_event *event, char *buf, int size)
{
	char fn[256];

	if (!event || !buf) {
		errno = EINVAL;
		return -1;
	}

	memset(fn, 0, 256);
	memset(buf, 0, size);
	snprintf(fn, 255, "/proc/%d/fd/%d", getpid(), event->fd);

	if (readlink(fn, buf, size - 1) == -1)
		return -1;

	return 0;
}

