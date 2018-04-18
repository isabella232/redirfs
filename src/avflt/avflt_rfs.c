/*
 * AVFlt: Anti-Virus Filter
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Original work:
 * Copyright 2008 - 2010 Frantisek Hrbata
 * All rights reserved.
 *
 * Modified work:
 * Copyright 2015 Cisco Systems, Inc.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "avflt.h"

static int avflt_should_check(struct file *file)
{
	if (avflt_is_stopped())
		return 0;

	if (avflt_proc_allow(current->tgid))
		return 0;

	if (avflt_trusted_allow(current->tgid))
		return 0;
	
	if (!file->f_dentry->d_inode)
		return 0;

	if (!i_size_read(file->f_dentry->d_inode))
		return 0;

	return 1;
}

static int avflt_check_cache(struct file *file, int type)
{
	struct avflt_root_data *root_data;
	struct avflt_inode_data *inode_data;
	int state = 0;
	int wc;

	if (!atomic_read(&avflt_cache_enabled))
		return 0;

	root_data = avflt_get_root_data_inode(file->f_dentry->d_inode);
	if (!root_data)
		return 0;

	if (!atomic_read(&root_data->cache_enabled)) {
		avflt_put_root_data(root_data);
		return 0;
	}

	inode_data = avflt_get_inode_data_inode(file->f_dentry->d_inode);
	if (!inode_data) {
		avflt_put_root_data(root_data);
		return 0;
	}

	wc = atomic_read(&file->f_dentry->d_inode->i_writecount);

	spin_lock(&inode_data->lock);

	if (wc == 1) {
		if (!(file->f_mode & FMODE_WRITE))
			inode_data->inode_cache_ver++;

		else if (type == AVFLT_EVENT_CLOSE)
			inode_data->inode_cache_ver++;

	} else if (wc > 1)
		inode_data->inode_cache_ver++;

	if (inode_data->root_data != root_data)
		goto exit;

	if (inode_data->root_cache_ver != atomic_read(&root_data->cache_ver))
		goto exit;

	if (inode_data->cache_ver != inode_data->inode_cache_ver)
		goto exit;

	state = inode_data->state;
exit:
	spin_unlock(&inode_data->lock);
	avflt_put_inode_data(inode_data);
	avflt_put_root_data(root_data);
	return state;
}

static enum redirfs_rv avflt_eval_res(int rv, struct redirfs_args *args)
{
	if (rv < 0) {
		args->rv.rv_int = rv;
		return REDIRFS_STOP;
	} 

	if (rv == AVFLT_FILE_INFECTED) {
		args->rv.rv_int = -EPERM;
		return REDIRFS_STOP;
	}

	return REDIRFS_CONTINUE;
}

static enum redirfs_rv avflt_check_rename(struct dentry *new_dentry, int type, struct redirfs_args *args)
{
	char *filename = NULL;
	struct file *file = NULL;
	int err = -1;
	int allow_on_timeout = 0;
	int timed_out = 0;
	enum redirfs_rv rv = REDIRFS_CONTINUE;

	/* Check if filter is running and whether process is trusted */

	if (avflt_is_stopped()) {
		return REDIRFS_CONTINUE;
	}

	if (avflt_proc_allow(current->tgid)) {
		return REDIRFS_CONTINUE;
	}

	if (avflt_trusted_allow(current->tgid)) {
		return REDIRFS_CONTINUE;
	}

	/* Check if the previous request timed out */

	timed_out = atomic_read(&avflt_timed_out);
	if (timed_out) {

		/* Force any waiting thread to wake up even though the request will
		 * not be enqueued.  In the event that a thread is ready and waiting
		 * but the timed-out condition is still set, this wake-up provides
		 * an opportunity to break from waiting and clear the timed-out
		 * condition. */
		wake_up_interruptible(&avflt_request_available);

		/* Proceed with configured behavior */
		allow_on_timeout = atomic_read(&avflt_allow_on_timeout);

		if (allow_on_timeout) {
			goto exit;
		}
		args->rv.rv_int = -ETIMEDOUT;
		rv = REDIRFS_STOP;
		goto exit;
	}

	filename = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!filename) {
		printk(KERN_WARNING "avflt: filename allocation failed\n");
		goto exit;
	}

	err = avflt_get_filename(new_dentry, filename, PAGE_SIZE);
	if (err) {
		printk(KERN_ERR "avflt: avflt_get_filename failed(%d)\n", err);
		goto exit;
	}

	err = avflt_process_request(file, filename, type);
	if (err == -ETIMEDOUT) {
		allow_on_timeout = atomic_read(&avflt_allow_on_timeout);

		if (allow_on_timeout) {
			goto exit;
		}
		args->rv.rv_int = -ETIMEDOUT;
		rv = REDIRFS_STOP;
	} else if (err) {
		rv = avflt_eval_res(err, args);
	}

exit:
	kfree(filename);

	return rv;
}

static enum redirfs_rv avflt_check_file(struct file *file, int type,
		struct redirfs_args *args)
{
	enum redirfs_rv redirfs_rv = REDIRFS_CONTINUE;
	char *filename = NULL;
	int allow_on_timeout;
	int timed_out;
	int rv;
	int wc;

	if (!avflt_should_check(file))
		return REDIRFS_CONTINUE;

	/* Ignore close events where there are no writers */
	if (type == AVFLT_EVENT_CLOSE) {
		wc = atomic_read(&file->f_dentry->d_inode->i_writecount);
		if (wc < 1) {
			return REDIRFS_CONTINUE;
		}
	}

	rv = avflt_check_cache(file, type);
	if (rv)
		return avflt_eval_res(rv, args);


	/* Check if the previous request timed out */

	timed_out = atomic_read(&avflt_timed_out);
	if (timed_out) {

		/* Force any waiting thread to wake up even though the request will
		 * not be enqueued.  In the event that a thread is ready and waiting
		 * but the timed-out condition is still set, this wake-up provides
		 * an opportunity to break from waiting and clear the timed-out
		 * condition. */
		wake_up_interruptible(&avflt_request_available);

		/* Proceed with configured behavior */
		allow_on_timeout = atomic_read(&avflt_allow_on_timeout);

		if (allow_on_timeout) {
			goto exit;
		}
		args->rv.rv_int = -ETIMEDOUT;
		rv = REDIRFS_STOP;
		goto exit;
	}

#ifdef AVFLT_INCLUDE_FILENAME_IN_FILE_EVENTS
	/* Attempt to get file name.  Since for file events the file descriptor
	 * is always provided, populating the path string is only best effort. */
	filename = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!filename) {
		printk(KERN_WARNING "avflt: filename allocation failed\n");
	} else {
		int err = avflt_get_filename(file->f_dentry, filename, PAGE_SIZE);
		if (err) {
			printk(KERN_WARNING "avflt: avflt_get_filename failed(%d)\n", err);
			kfree(filename);
			filename = NULL;
		}
	}
#endif

	rv = avflt_process_request(file, filename, type);
	if (rv == -ETIMEDOUT) {
		allow_on_timeout = atomic_read(&avflt_allow_on_timeout);

		if (allow_on_timeout) {
			redirfs_rv = REDIRFS_CONTINUE;
			goto exit;
		}
		args->rv.rv_int = -ETIMEDOUT;
		redirfs_rv = REDIRFS_STOP;
	} else if (rv) {
		redirfs_rv = avflt_eval_res(rv, args);
	}

exit:
	kfree(filename);

	return redirfs_rv;
}

#ifndef AVFLT_DISABLE_FILE_OPEN_MONITORING
static enum redirfs_rv avflt_pre_open(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_open.file;

	return avflt_check_file(file, AVFLT_EVENT_OPEN, args);
}
#endif

static enum redirfs_rv avflt_post_release(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_release.file;

	return avflt_check_file(file, AVFLT_EVENT_CLOSE, args);
}

enum redirfs_rv avflt_rename_to(redirfs_context context,
        struct redirfs_args *args)
{
	struct dentry *dentry = args->args.i_rename.new_dentry;

	return avflt_check_rename(dentry, AVFLT_EVENT_RENAME_TO, args);
}

static int avflt_activate(void)
{
	avflt_invalidate_cache();
	return redirfs_activate_filter(avflt);
}

static int avflt_add_path(struct redirfs_path_info *info)
{
	struct avflt_root_data *data;
	redirfs_path path;
	redirfs_root root;

	path = redirfs_add_path(avflt, info);
	if (IS_ERR(path))
		return PTR_ERR(path);

	root = redirfs_get_root_path(path);
	redirfs_put_path(path);
	if (!root)
		return 0;

	data = avflt_attach_root_data(root);

	redirfs_put_root(root);
	avflt_put_root_data(data);
	
	return 0;
}

redirfs_filter avflt;

static struct redirfs_filter_operations avflt_ops = {
	.activate = avflt_activate,
	.add_path = avflt_add_path,
	.post_rename = avflt_rename_to
};

static struct redirfs_filter_info avflt_info = {
	.owner = THIS_MODULE,
	.name = AVFLT_NAME,
	.priority = AVFLT_PRIORITY,
	.active = 1,
	.ops = &avflt_ops
};

static struct redirfs_op_info avflt_op_info[] = {
#ifndef AVFLT_DISABLE_FILE_OPEN_MONITORING
	{REDIRFS_REG_FOP_OPEN, avflt_pre_open, NULL},
#endif
	{REDIRFS_REG_FOP_RELEASE, avflt_post_release, NULL},
	{REDIRFS_OP_END, NULL, NULL}
};

int avflt_rfs_init(void)
{
	int err;
	int rv;

	avflt = redirfs_register_filter(&avflt_info);
	if (IS_ERR(avflt)) {
		rv = PTR_ERR(avflt);
		printk(KERN_ERR "avflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(avflt, avflt_op_info);
	if (rv) {
		printk(KERN_ERR "avflt: set operations failed(%d)\n", rv);
		goto error;
	}

	return 0;
error:
	err = redirfs_unregister_filter(avflt);
	if (err) {
		printk(KERN_ERR "avflt: unregister filter failed(%d)\n", err);
		return 0;
	}

	redirfs_delete_filter(avflt);
	return rv;
}

void avflt_rfs_exit(void)
{
	redirfs_delete_filter(avflt);
}

int avflt_get_filename(struct dentry *dentry, char *buf, int size)
{
	redirfs_root root;
	int root_valid = 0;
	redirfs_path* paths;
	int paths_valid = 0;
	redirfs_path path;
	struct redirfs_path_info *path_info = NULL;
	int path_info_valid = 0;
	int err = -1;
	int ret = -1;

	/* Obtain the destination path of this rename event.  Based on code
	 * example in "mvflt" (function mvflt_rename_in). */

	root = redirfs_get_root_dentry(avflt, dentry);
	if (!root) {
		printk(KERN_WARNING "avflt: redirfs_get_root_dentry: NULL\n");
		goto exit;
	}
	root_valid = 1;

	paths = redirfs_get_paths_root(avflt, root);
	path = paths[0];
	if (!path) {
		printk(KERN_WARNING "avflt: redirfs_get_paths_root: NULL\n");
		goto exit;
	}
	paths_valid = 1;

	path_info = redirfs_get_path_info(avflt, path);
	if (IS_ERR(path_info)) {
		printk(KERN_ERR "avflt: redirfs_get_path_info failed(%ld)\n",
			PTR_ERR(path_info));
		goto exit;
	}
	path_info_valid = 1;

	err = redirfs_get_filename(path_info->mnt, dentry, buf, size);
	if (err) {
		printk(KERN_ERR "avflt: redirfs_get_filename failed(%d)\n", err);
		goto exit;
	}

	ret = 0;

exit:
	if (path_info_valid) {
		redirfs_put_path_info(path_info);
	}

	if (paths_valid) {
		redirfs_put_paths(paths);
	}

	if (root_valid) {
		redirfs_put_root(root);
	}

	return ret;
}
