/*
 * AIO backing store
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 * Copyright (C) 2011 Alexander Nezhinsky <alexandern@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <pthread.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include "bs_thread.h"

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif

#define AIO_MAX_IODEPTH    128


struct bs_aio_info {
	/* Placing struct bs_thread_info at the beginning of
	 * bs_aio_info allows for a kind of single-inheritance of
	 * bs_thread_cmd_submit implementation. Don't put any other
	 * elements here. */
	struct bs_thread_info thread_info;
	struct list_head dev_list_entry;
	io_context_t ctx;

	struct list_head cmd_wait_list;
	unsigned int nwaiting;
	unsigned int npending;
	unsigned int iodepth;

	int resubmit;

	struct scsi_lu *lu;
	int evt_fd;

	struct iocb iocb_arr[AIO_MAX_IODEPTH];
	struct iocb *piocb_arr[AIO_MAX_IODEPTH];
	struct io_event io_evts[AIO_MAX_IODEPTH];

	pthread_t sync_thread;
	struct list_head sync_commands;
	pthread_cond_t sync_queue_cond;
	pthread_mutex_t sync_queue_lock;

	struct list_head sync_done;
	pthread_mutex_t sync_done_lock;
	int evt_sync_done;
};

static struct list_head bs_aio_dev_list = LIST_HEAD_INIT(bs_aio_dev_list);

static inline struct bs_aio_info *BS_AIO_I(struct scsi_lu *lu)
{
	return (struct bs_aio_info *) ((char *)lu + sizeof(*lu));
}

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}


static void bs_aio_iocb_prep(struct bs_aio_info *info, int idx,
			     struct scsi_cmd *cmd)
{
	struct iocb *iocb = &info->iocb_arr[idx];
	unsigned int scsi_op = (unsigned int)cmd->scb[0];

	iocb->data = cmd;
	iocb->key = 0;
	iocb->aio_reqprio = 0;
	iocb->aio_fildes = info->lu->fd;

	switch (scsi_op) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		iocb->aio_lio_opcode = IO_CMD_PWRITE;
		iocb->u.c.buf = scsi_get_out_buffer(cmd);
		iocb->u.c.nbytes = scsi_get_out_length(cmd);

		dprintf("prep WR cmd:%p op:%x buf:0x%p sz:%lx\n",
			cmd, scsi_op, iocb->u.c.buf, iocb->u.c.nbytes);
		break;

	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		iocb->aio_lio_opcode = IO_CMD_PREAD;
		iocb->u.c.buf = scsi_get_in_buffer(cmd);
		iocb->u.c.nbytes = scsi_get_in_length(cmd);

		dprintf("prep RD cmd:%p op:%x buf:0x%p sz:%lx\n",
			cmd, scsi_op, iocb->u.c.buf, iocb->u.c.nbytes);
		break;

	default:
		return;
	}

	iocb->u.c.offset = cmd->offset;
	iocb->u.c.flags |= (1 << 0); /* IOCB_FLAG_RESFD - use eventfd file desc. */
	iocb->u.c.resfd = info->evt_fd;
}

static int bs_aio_submit_dev_batch(struct bs_aio_info *info)
{
	int nsubmit, nsuccess;
	struct scsi_cmd *cmd, *next;
	int i = 0;

	nsubmit = info->iodepth - info->npending; /* max allowed to submit */
	if (nsubmit > info->nwaiting)
		nsubmit = info->nwaiting;

	dprintf("nsubmit:%d waiting:%d pending:%d, tgt:%d lun:%"PRId64 "\n",
		nsubmit, info->nwaiting, info->npending,
		info->lu->tgt->tid, info->lu->lun);

	if (!nsubmit)
		return 0;

	list_for_each_entry_safe(cmd, next, &info->cmd_wait_list, bs_list) {
		bs_aio_iocb_prep(info, i, cmd);
		list_del(&cmd->bs_list);
		if (++i == nsubmit)
			break;
	}

	nsuccess = io_submit(info->ctx, nsubmit, info->piocb_arr);
	if (unlikely(nsuccess < 0)) {
		if (nsuccess == -EAGAIN) {
			eprintf("delayed submit %d cmds to tgt:%d lun:%"PRId64 "\n",
				nsubmit, info->lu->tgt->tid, info->lu->lun);
			nsuccess = 0; /* leave the dev pending with all cmds */
		}
		else {
			eprintf("failed to submit %d cmds to tgt:%d lun:%"PRId64
				", err: %d\n",
				nsubmit, info->lu->tgt->tid,
				info->lu->lun, -nsuccess);
			for (i = nsubmit - 1; i >= 0; i--) {
				cmd = info->iocb_arr[i].data;
				clear_cmd_async(cmd);
				info->nwaiting--;
				if (!info->nwaiting)
					list_del(&info->dev_list_entry);
			}
			return nsuccess;
		}
	}
	if (unlikely(nsuccess < nsubmit)) {
		for (i=nsubmit-1; i >= nsuccess; i--) {
			cmd = info->iocb_arr[i].data;
			list_add(&cmd->bs_list, &info->cmd_wait_list);
		}
	}

	info->npending += nsuccess;
	info->nwaiting -= nsuccess;
	/* if no cmds remain, remove the dev from the pending list */
	if (likely(!info->nwaiting))
			list_del(&info->dev_list_entry);

	dprintf("submitted %d of %d cmds to tgt:%d lun:%"PRId64
		", waiting:%d pending:%d\n",
		nsuccess, nsubmit, info->lu->tgt->tid, info->lu->lun,
		info->nwaiting, info->npending);
	return 0;
}

static int bs_aio_submit_all_devs(void)
{
	struct bs_aio_info *dev_info, *next_dev;
	int err;

	/* pass over all devices having some queued cmds and submit */
	list_for_each_entry_safe(dev_info, next_dev, &bs_aio_dev_list, dev_list_entry) {
		err = bs_aio_submit_dev_batch(dev_info);
		if (unlikely(err))
			return err;
	}
	return 0;
}

static int bs_aio_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	struct bs_aio_info *info = BS_AIO_I(lu);
	unsigned int scsi_op = (unsigned int)cmd->scb[0];

	switch (scsi_op) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		break;

	case WRITE_SAME:
	case WRITE_SAME_16:
	case UNMAP:
		return bs_thread_cmd_submit(cmd);

	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16: {
		/* FIXME: it can be the case that sync submission is
		 * better done through bs_aio_submit_dev_batch, making
		 * correct nwaiting & npending accounting easier and
		 * ensuring depth limit applies to syncs as well.
		 */
		int should_signal;
		set_cmd_async(cmd);

		pthread_mutex_lock(&info->sync_queue_lock);
		should_signal = list_empty(&info->sync_commands);
		list_add_tail(&cmd->bs_list,&info->sync_commands);
		pthread_mutex_unlock(&info->sync_queue_lock);

		if (should_signal)
			pthread_cond_signal(&info->sync_queue_cond);
	}
		return 0;
	default:
		dprintf("skipped cmd:%p op:%x\n", cmd, scsi_op);
		return 0;
	}

	list_add_tail(&cmd->bs_list, &info->cmd_wait_list);
	if (!info->nwaiting)
		list_add_tail(&info->dev_list_entry, &bs_aio_dev_list);
	info->nwaiting++;
	set_cmd_async(cmd);

	if (!cmd_not_last(cmd)) /* last cmd in batch */
		return bs_aio_submit_all_devs();

	if (info->nwaiting == info->iodepth - info->npending)
		return bs_aio_submit_dev_batch(info);

	return 0;
}

static void bs_aio_complete_one(struct io_event *ep)
{
	struct scsi_cmd *cmd = (void *)(unsigned long)ep->data;
	uint32_t length;
	int result;

	switch (cmd->scb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = scsi_get_out_length(cmd);
		break;
	default:
		length = scsi_get_in_length(cmd);
		break;
	}

	if (likely(ep->res == length))
		result = SAM_STAT_GOOD;
	else {
		sense_data_build(cmd, MEDIUM_ERROR, 0);
		result = SAM_STAT_CHECK_CONDITION;
	}
	dprintf("cmd: %p\n", cmd);
	target_cmd_io_done(cmd, result);
}

static void bs_aio_get_sync_done(int fd, int events, void *data)
{
	struct bs_aio_info *info = data;
	int ret;
	/* read from eventfd returns 8-byte int, fails with the error EINVAL
	   if the size of the supplied buffer is less than 8 bytes */
	uint64_t evts_complete;
	LIST_HEAD(done);
	struct scsi_cmd *cmd, *next;

	ret = read(info->evt_sync_done, &evts_complete, sizeof(evts_complete));

	if (unlikely(ret < 0)) {
		eprintf("failed to read fdatasync completions, %m\n");
		return;
	}

	pthread_mutex_lock(&info->sync_done_lock);
	list_splice_init(&info->sync_done,&done);
	pthread_mutex_unlock(&info->sync_done_lock);

	list_for_each_entry_safe(cmd, next, &done, bs_list) {
		target_cmd_io_done(cmd, scsi_get_result(cmd));
		list_del(&cmd->bs_list);
	}
}

static void bs_aio_get_completions(int fd, int events, void *data)
{
	struct bs_aio_info *info = data;
	int i, ret;
	/* read from eventfd returns 8-byte int, fails with the error EINVAL
	   if the size of the supplied buffer is less than 8 bytes */
	uint64_t evts_complete;
	unsigned int ncomplete, nevents;

retry_read:
	ret = read(info->evt_fd, &evts_complete, sizeof(evts_complete));
	if (unlikely(ret < 0)) {
		eprintf("failed to read AIO completions, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto retry_read;

		return;
	}
	ncomplete = (unsigned int) evts_complete;

	while (ncomplete) {
		nevents = min_t(unsigned int, ncomplete, ARRAY_SIZE(info->io_evts));
retry_getevts:
		ret = io_getevents(info->ctx, 1, nevents, info->io_evts, NULL);
		if (likely(ret > 0)) {
			nevents = ret;
			info->npending -= nevents;
		} else {
			if (ret == -EINTR)
				goto retry_getevts;
			eprintf("io_getevents failed, err:%d\n", -ret);
			return;
		}
		dprintf("got %d ioevents out of %d, pending %d\n",
			nevents, ncomplete, info->npending);

		for (i = 0; i < nevents; i++)
			bs_aio_complete_one(&info->io_evts[i]);
		ncomplete -= nevents;
	}

	if (info->nwaiting) {
		dprintf("submit waiting cmds to tgt:%d lun:%"PRId64 "\n",
			info->lu->tgt->tid, info->lu->lun);
		bs_aio_submit_dev_batch(info);
	}
}

static int bs_aio_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	struct bs_aio_info *info = BS_AIO_I(lu);
	int ret, afd, sfd;
	uint32_t blksize = 0;

	info->iodepth = AIO_MAX_IODEPTH;
	eprintf("create aio context for tgt:%d lun:%"PRId64 ", max iodepth:%d\n",
		info->lu->tgt->tid, info->lu->lun, info->iodepth);
	ret = io_setup(info->iodepth, &info->ctx);
	if (ret) {
		eprintf("failed to create aio context, %m\n");
		return -1;
	}

	afd = eventfd(0, O_NONBLOCK);
	if (afd < 0) {
		eprintf("failed to create eventfd for tgt:%d lun:%"PRId64 ", %m\n",
			info->lu->tgt->tid, info->lu->lun);
		ret = afd;
		goto close_ctx;
	}
	dprintf("eventfd:%d for tgt:%d lun:%"PRId64 "\n",
		afd, info->lu->tgt->tid, info->lu->lun);

	ret = tgt_event_add(afd, EPOLLIN, bs_aio_get_completions, info);
	if (ret)
		goto close_afd;
	info->evt_fd = afd;

	sfd = eventfd(0, O_NONBLOCK);
	if (sfd < 0) {
		eprintf("failed to create eventfd for tgt:%d lun:%"PRId64 ", %m\n",
			info->lu->tgt->tid, info->lu->lun);
		ret = sfd;
		goto remove_tgt_evt_afd;
	}
	dprintf("eventfd:%d for tgt:%d lun:%"PRId64 "\n",
		sfd, info->lu->tgt->tid, info->lu->lun);

	ret = tgt_event_add(sfd, EPOLLIN, bs_aio_get_sync_done, info);
	if (ret)
		goto close_sfd;
	info->evt_sync_done = sfd;


	eprintf("open %s, RW, O_DIRECT for tgt:%d lun:%"PRId64 "\n",
		path, info->lu->tgt->tid, info->lu->lun);
	*fd = backed_file_open(path, O_RDWR|O_LARGEFILE|O_DIRECT, size,
				&blksize);
	/* If we get access denied, try opening the file in readonly mode */
	if (*fd == -1 && (errno == EACCES || errno == EROFS)) {
		eprintf("open %s, READONLY, O_DIRECT for tgt:%d lun:%"PRId64 "\n",
			path, info->lu->tgt->tid, info->lu->lun);
		*fd = backed_file_open(path, O_RDONLY|O_LARGEFILE|O_DIRECT,
				       size, &blksize);
		lu->attrs.readonly = 1;
	}
	if (*fd < 0) {
		eprintf("failed to open %s, for tgt:%d lun:%"PRId64 ", %m\n",
			path, info->lu->tgt->tid, info->lu->lun);
		ret = *fd;
		goto remove_tgt_evt_sfd;
	}

	eprintf("%s opened successfully for tgt:%d lun:%"PRId64 "\n",
		path, info->lu->tgt->tid, info->lu->lun);

	if (!lu->attrs.no_auto_lbppbe)
		update_lbppbe(lu, blksize);

	return 0;

remove_tgt_evt_sfd:
	tgt_event_del(sfd);
close_sfd:
	close(sfd);
remove_tgt_evt_afd:
	tgt_event_del(afd);
close_afd:
	close(afd);
close_ctx:
	io_destroy(info->ctx);
	return ret;
}

static void bs_aio_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

/* Unlock mutex even if thread is cancelled */
static void mutex_cleanup(void *mutex)
{
	pthread_mutex_unlock(mutex);
}

static void bs_aio_thread_request(struct scsi_cmd *cmd)
{
	int ret, fd = cmd->dev->fd;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;
	char *tmpbuf;
	size_t blocksize;
	uint64_t offset = cmd->offset;
	uint32_t tl     = cmd->tl;

	ret = length = 0;
	key = asc = 0;

	switch (cmd->scb[0])
	{
	case WRITE_SAME:
	case WRITE_SAME_16:
		/* WRITE_SAME used to punch hole in file */
		if (cmd->scb[1] & 0x08) {
			ret = unmap_file_region(fd, offset, tl);
			if (ret != 0) {
				eprintf("Failed to punch hole for WRITE_SAME"
					" command\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = HARDWARE_ERROR;
				asc = ASC_INTERNAL_TGT_FAILURE;
				break;
			}
			break;
		}
		while (tl > 0) {
			blocksize = 1 << cmd->dev->blk_shift;
			tmpbuf = scsi_get_out_buffer(cmd);

			switch(cmd->scb[1] & 0x06) {
			case 0x02: /* PBDATA==0 LBDATA==1 */
				put_unaligned_be32(offset, tmpbuf);
				break;
			case 0x04: /* PBDATA==1 LBDATA==0 */
				/* physical sector format */
				put_unaligned_be64(offset, tmpbuf);
				break;
			}

			ret = pwrite64(fd, tmpbuf, blocksize, offset);
			if (ret != blocksize)
				set_medium_error(&result, &key, &asc);

			offset += blocksize;
			tl     -= blocksize;
		}
		break;
	case UNMAP:
		if (!cmd->dev->attrs.thinprovisioning) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
			break;
		}

		length = scsi_get_out_length(cmd);
		tmpbuf = scsi_get_out_buffer(cmd);

		if (length < 8)
			break;

		length -= 8;
		tmpbuf += 8;

		while (length >= 16) {
			offset = get_unaligned_be64(&tmpbuf[0]);
			offset = offset << cmd->dev->blk_shift;

			tl = get_unaligned_be32(&tmpbuf[8]);
			tl = tl << cmd->dev->blk_shift;

			if (offset + tl > cmd->dev->size) {
				eprintf("UNMAP beyond EOF\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = ILLEGAL_REQUEST;
				asc = ASC_LBA_OUT_OF_RANGE;
				break;
			}

			if (tl > 0) {
				if (unmap_file_region(fd, offset, tl) != 0) {
					eprintf("Failed to punch hole for"
						" UNMAP at offset:%" PRIu64
						" length:%d\n",
						offset, tl);
					result = SAM_STAT_CHECK_CONDITION;
					key = HARDWARE_ERROR;
					asc = ASC_INTERNAL_TGT_FAILURE;
					break;
				}
			}

			length -= 16;
			tmpbuf += 16;
		}
		break;
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, offset);
		sense_data_build(cmd, key, asc);
	}
}

static void *bs_aio_sync_worker(void* arg)
{
	struct bs_aio_info *info = arg;
	int should_signal;
	int ret;
	LIST_HEAD(commands);
	struct scsi_cmd *cmd, *next;

	while(1) {
		pthread_mutex_lock(&info->sync_queue_lock);
		pthread_cleanup_push(mutex_cleanup,&info->sync_queue_lock);
		while(list_empty(&info->sync_commands)) {
			pthread_cond_wait(&info->sync_queue_cond, &info->sync_queue_lock);
		}
		list_splice_init(&info->sync_commands,&commands);
		pthread_cleanup_pop(1);
		ret = fdatasync(info->lu->fd);
		list_for_each_entry_safe(cmd, next, &commands, bs_list) {
			if (ret<0) {
				scsi_set_result(cmd, SAM_STAT_CHECK_CONDITION);
				sense_data_build(cmd, MEDIUM_ERROR, 0);
			} else {
				scsi_set_result(cmd, SAM_STAT_GOOD);
			}
		}

		pthread_mutex_lock(&info->sync_done_lock);
		should_signal = list_empty(&info->sync_done);
		list_splice_init(&commands,&info->sync_done);
		pthread_mutex_unlock(&info->sync_done_lock);
		if (should_signal) {
			eventfd_write(info->evt_sync_done, 1);
		}
	}
}

static tgtadm_err bs_aio_init(struct scsi_lu *lu, char *bsopts)
{
	struct bs_aio_info *info = BS_AIO_I(lu);
	int i,res;

	memset(info, 0, sizeof(*info));
	res = bs_thread_open(&info->thread_info,bs_aio_thread_request,nr_iothreads);
	if (res)
		return res;
	INIT_LIST_HEAD(&info->dev_list_entry);
	INIT_LIST_HEAD(&info->cmd_wait_list);
	info->lu = lu;

	for (i=0; i < ARRAY_SIZE(info->iocb_arr); i++)
		info->piocb_arr[i] = &info->iocb_arr[i];

	INIT_LIST_HEAD(&info->sync_commands);
	INIT_LIST_HEAD(&info->sync_done);
	pthread_cond_init(&info->sync_queue_cond,NULL);
	pthread_mutex_init(&info->sync_queue_lock,NULL);
	pthread_mutex_init(&info->sync_done_lock,NULL);

	pthread_create(&info->sync_thread, NULL, bs_aio_sync_worker, info);

	return TGTADM_SUCCESS;
}

static void bs_aio_exit(struct scsi_lu *lu)
{
	struct bs_aio_info *info = BS_AIO_I(lu);

	bs_thread_close(&info->thread_info);
	close(info->evt_fd);
	io_destroy(info->ctx);
	pthread_cancel(info->sync_thread);
	pthread_join(info->sync_thread,NULL);
}

static struct backingstore_template aio_bst = {
	.bs_name		= "aio",
	.bs_datasize    	= sizeof(struct bs_aio_info),
	.bs_init		= bs_aio_init,
	.bs_exit		= bs_aio_exit,
	.bs_open		= bs_aio_open,
	.bs_close       	= bs_aio_close,
	.bs_cmd_submit  	= bs_aio_cmd_submit,
};

__attribute__((constructor)) static void register_bs_module(void)
{
	register_backingstore_template(&aio_bst);
}

