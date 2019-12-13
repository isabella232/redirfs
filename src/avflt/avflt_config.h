/*
 * Configuration macros to control how Avflt is compiled
 *
 * Copyright 2015 Cisco Systems, Inc.
 */
#ifndef _AVFLT_CONFIG_H
#define _AVFLT_CONFIG_H

#define AVFLT_NAME		"ampavflt"
#define AVFLT_DESCRIPTION	"Cisco Anti-Virus Filter "\
				"for the RedirFS Framework"
#define AVFLT_VERSION		"1.3"
#define AVFLT_LICENSE		"GPL"
#define AVFLT_AUTHOR		"Frantisek Hrbata "\
				"<frantisek.hrbata@redirfs.org>; "\
				"Modifications by Cisco Systems "\
				"<www.cisco.com>"
#define AVFLT_BANNER		AVFLT_DESCRIPTION " " AVFLT_VERSION ". " \
				"Based on RedirFS AVFlt 0.6 "\
				"<www.redirfs.org>\n"
#define AVFLT_PRIORITY		851000000

/* By default open, close and rename events are monitored.  Defining the
 * AVFLT_DISABLE_FILE_OPEN_MONITORING macro disables file open monitoring.
 * This reduces overhead and is appropriate when the application is only
 * interested in file change notifications and do not actively block access to
 * files.
 */
#define AVFLT_DISABLE_FILE_OPEN_MONITORING

/* For file open and close events, an open file descriptor is always provided
 * which the application can optionally use to obtain the file name.  Defining
 * the AVFLT_INCLUDE_FILENAME_IN_FILE_EVENTS macro causes the file name to be
 * internally generated and included in addition to the file descriptor.
 * Enabling this option adds overhead but can be helpful in some debug
 * situations.
 */
//#define AVFLT_INCLUDE_FILENAME_IN_FILE_EVENTS

#endif
