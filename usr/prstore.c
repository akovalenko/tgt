/*
 * PR store routines
 *
 * Copyright (C) 2013 Alexander Gordeev <agordeev@parallels.com>
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
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include "prstore.h"

enum pr_req_type {
	PR_REQ_OPEN,
	PR_REQ_UPDATE,
	PR_REQ_DELETE,
	PR_REQ_CLOSE
};

struct pr_request {
	enum pr_req_type type;
	struct list_head list;
	union {
		struct {
			struct scsi_lu *lu;
		} open;

		struct {
			struct registration *reg;
			struct scsi_cmd *cmd;
		} update;

		struct {
			int slot;
			struct scsi_cmd *cmd;
		} del;

		struct {
			struct scsi_lu *lu;
		} close;
	};
};

typedef void (*reqhandler_t)(struct pr_request *req);

static LIST_HEAD(incoming_list);
static pthread_mutex_t incoming_lock;
static pthread_cond_t incoming_cond;

static LIST_HEAD(done_list);
static pthread_mutex_t done_lock;
static int done_fd[2];

static pthread_t pr_thread;
static int pr_thread_run;

#define PR_INIT_SLOTS	16
#define BITS_PER_LONG	(sizeof(long) * 8)

/* TODO:
 * 1. support preempt
 * 2. ensure that LUN with PR store is destroyed the right way
 * 3. remove mutexes (they can block), move requests through pipes instead (?)
 * 4. store initiator names instead of full transport ids (?)
 * 5. honor APTPL bit
 * 6. add crc32 sum to each stored registration
 * 7. fix man
 * 8. check if it can be setup through targets.conf
 */


/* Bitset ops */

static inline int bitset_slots_to_size(int nslots)
{
	return (nslots + BITS_PER_LONG - 1) / BITS_PER_LONG;
}

static inline int bitset_slots_to_bytes(int nslots)
{
	return (nslots + BITS_PER_LONG - 1) / 8;
}

static int bitset_ffs(long *bs, int slots)
{
	int w;

	for (w = 0; bs[w] == 0; ++w)
		if (w >= bitset_slots_to_size(slots))
			return -1;
	return w * sizeof(long) * 8 + ffsl(bs[w]) - 1;
}

static inline void bitset_set(long *bs, int index)
{
	bs[index / (sizeof(long) * 8)] |= 1L << (index % (sizeof(long) * 8));
}

static inline void bitset_unset(long *bs, int index)
{
	bs[index / (sizeof(long) * 8)] &= ~(1L << (index % (sizeof(long) * 8)));
}


/* Safe write and read */

/* returns sz if ok or -errno if error */
static int swrite(int fd, void *buf, int sz)
{
	int w = sz;

	while (w) {
		int n = write(fd, buf, w);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		buf += n;
		w -= n;
	}
	return sz;
}

/* returns number of bytes read or -errno if error */
static int sread(int fd, void *buf, int sz)
{
	int r = 0;
	while (sz) {
		int n = read(fd, buf, sz);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		buf += n;
		r += n;
		sz -= n;
	}
	return r;
}


/* Callbacks that will be executed after completion in the main thread */

static void done_open_req(struct pr_request *req)
{
}

static void done_update_req(struct pr_request *req)
{
	dprintf("back to tgtd, %p\n", req->update.cmd);
	target_cmd_io_done(req->update.cmd, scsi_get_result(req->update.cmd));
}

static void done_delete_req(struct pr_request *req)
{
	dprintf("back to tgtd, %p\n", req->del.cmd);
	target_cmd_io_done(req->del.cmd, scsi_get_result(req->del.cmd));
}

static void done_close_req(struct pr_request *req)
{
}

reqhandler_t done_handlers[] = {
	[PR_REQ_OPEN] = done_open_req,
	[PR_REQ_UPDATE] = done_update_req,
	[PR_REQ_DELETE] = done_delete_req,
	[PR_REQ_CLOSE] = done_close_req
};

static void pr_request_done(int fd, int events, void *data)
{
	struct pr_request *req;
	int ack, ret;

	ret = read(done_fd[0], &ack, sizeof(ack));
	if (ret < 0) {
		eprintf("wrong wakeup\n");
		return;
	}

	pthread_mutex_lock(&done_lock);
	if (list_empty(&done_list)) {
		pthread_mutex_unlock(&done_lock);
		return;
	}

	req = list_first_entry(&done_list,
			       struct pr_request, list);
	list_del(&req->list);
	pthread_mutex_unlock(&done_lock);

	done_handlers[req->type](req);
	free(req);
}


/* PR thread logic */

static void clear_regs(struct list_head *list)
{
	struct registration *reg;

	while (!list_empty(list)) {
		reg = list_first_entry(list, struct registration, registration_siblings);
		list_del(&reg->registration_siblings);
		free(reg);
	}
}

static int enlarge_store(struct pr_store *prs, int nslots)
{
	off_t filesz;
	int bsz_old, bsz_new;
	void *ptr;
	int i;

	if (prs->nslots >= nslots)
		return 0;

	filesz = (off_t)nslots * sizeof(struct stored_registration);
	if (posix_fallocate(prs->fd, 0, filesz) < 0) {
		eprintf("failed to preallocate PR file: %s\n", strerror(errno));
		return -1;
	}

	bsz_old = bitset_slots_to_bytes(prs->nslots);
	bsz_new = bitset_slots_to_bytes(nslots);
	ptr = realloc(prs->free_slot_mask, bsz_new);
	if (!ptr) {
		eprintf("memory allocation failed\n");
		return -1;
	}
	prs->free_slot_mask = ptr;
	memset(ptr + bsz_old, 0, bsz_new - bsz_old);

	for (i = prs->nslots; i < nslots; ++i)
		bitset_set(prs->free_slot_mask, i);
	prs->nslots = nslots;

	return 0;
}

static int check_reservation(struct scsi_lu *lu, struct registration *reg)
{
	if (!reg->st.pr_type && !reg->st.pr_scope)
		return 0;

	switch (reg->st.pr_type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
	case PR_TYPE_EXCLUSIVE_ACCESS:
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY:
	case PR_TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case PR_TYPE_WRITE_EXCLUSIVE_ALLREG:
	case PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		break;
	default:
		eprintf("invalid PR type: %u\n", reg->st.pr_type);
		return -1;
	}

	if (reg->st.pr_scope != PR_LU_SCOPE) {
		eprintf("invalid PR scope: %u\n", reg->st.pr_scope);
		return -1;
	}

	if (!lu->pr_holder)
		lu->pr_holder = reg;

	return 0;
}

static tgtadm_err open_store(struct scsi_lu *lu)
{
	/* safe to use pr_dir here because we
	 * checked that it is set already */
	char path[strlen(lu->tgt->pr_dir) + 18];
	struct pr_store *prs = &lu->prs;
	struct stat st;
	struct registration *reg = NULL;
	LIST_HEAD(tmplist);
	ssize_t len;
	int i;

	if (snprintf(path, sizeof(path), "%s/%016llx", lu->tgt->pr_dir,
				(unsigned long long)lu->lun) != sizeof(path) - 1) {
		eprintf("failed to snprintf PR path\n");
		return TGTADM_UNKNOWN_ERR;
	}

	prs->fd = open(path, O_RDWR | O_CLOEXEC | O_CREAT, 0644);
	if (prs->fd < 0) {
		eprintf("failed to open PR file: %s\n", strerror(errno));
		return TGTADM_UNKNOWN_ERR;
	}

	if (fstat(prs->fd, &st) < 0) {
		eprintf("failed to stat PR file: %s\n", strerror(errno));
		goto fail_close;
	}

	prs->nslots = st.st_size / sizeof(struct stored_registration);
	prs->free_slot_mask = zalloc(bitset_slots_to_bytes(prs->nslots));
	if (!prs->free_slot_mask) {
		eprintf("memory allocation failed\n");
		goto fail_close;
	}

	for (i = 0; i < prs->nslots; ++i) {
		if (!reg) {
			reg = zalloc(sizeof(struct registration));
			if (!reg) {
				eprintf("memory allocation failed\n");
				goto fail_free_regs;
			}
		}
		len = sread(prs->fd, &reg->st, sizeof(struct stored_registration));
		if (len != sizeof(struct stored_registration)) {
			if (len < 0)
				eprintf("failed to read PR file: %s\n", strerror(errno));
			else if (len > 0)
				eprintf("partial read from PR file\n");
			else
				eprintf("unexpected end of PR file\n");
			free(reg);
			goto fail_free_regs;
		}

		if (reg->st.key && (check_reservation(lu, reg) == 0)) {
			reg->slot = i;
			list_add_tail(&reg->registration_siblings, &tmplist);
			reg = NULL;
		} else
			bitset_set(prs->free_slot_mask, i);
	}

	if (enlarge_store(prs, PR_INIT_SLOTS) < 0)
		goto fail_free_regs;

	list_splice_init(&tmplist, &lu->registration_list);

	return TGTADM_SUCCESS;

fail_free_regs:
	clear_regs(&tmplist);
	free(prs->free_slot_mask);
	prs->free_slot_mask = NULL;
fail_close:
	prs->nslots = 0;
	close(prs->fd);
	prs->fd = -1;
	prs->enable = 0;
	return TGTADM_UNKNOWN_ERR;
}

static void handle_open_req(struct pr_request *req)
{
	open_store(req->open.lu);
}

static int flush_reg(int fd, struct stored_registration *reg, off_t slot)
{
	if (lseek(fd, slot * sizeof(struct stored_registration), SEEK_SET) < 0) {
		eprintf("failed to lseek in PR file: %s\n", strerror(errno));
		return -1;
	}
	if (swrite(fd, reg, sizeof(struct stored_registration)) < 0) {
		eprintf("failed to write to PR file: %s\n", strerror(errno));
		return -1;
	}
	if (fdatasync(fd) < 0) {
		eprintf("failed to fdatasync PR file: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void handle_update_req(struct pr_request *req)
{
	struct pr_store *prs = &req->update.cmd->dev->prs;
	struct registration *reg = req->update.reg;

	if (!prs->enable)
		return;

	if (reg->slot == -1) {
		reg->slot = bitset_ffs(prs->free_slot_mask, prs->nslots);
		if (reg->slot == -1) {
			if (enlarge_store(prs, prs->nslots * 2) < 0) {
				scsi_set_result(req->update.cmd, SAM_STAT_CHECK_CONDITION);
				return;
			}
			reg->slot = bitset_ffs(prs->free_slot_mask, prs->nslots);
		}
		bitset_unset(prs->free_slot_mask, reg->slot);
	}

	if (flush_reg(prs->fd, &reg->st, reg->slot) < 0)
		scsi_set_result(req->update.cmd, SAM_STAT_CHECK_CONDITION);
}

static void handle_delete_req(struct pr_request *req)
{
	struct pr_store *prs = &req->del.cmd->dev->prs;
	struct stored_registration buf;

	if (!prs->enable)
		return;

	bitset_set(prs->free_slot_mask, req->del.slot);
	memset(&buf, 0, sizeof(struct stored_registration));
	if (flush_reg(prs->fd, &buf, req->del.slot) < 0)
		scsi_set_result(req->del.cmd, SAM_STAT_CHECK_CONDITION);
}

static void handle_close_req(struct pr_request *req)
{
	struct scsi_lu *lu = req->close.lu;
	struct pr_store *prs = &lu->prs;

	if (!prs->enable)
		return;

	free(prs->free_slot_mask);
	prs->free_slot_mask = NULL;
	prs->nslots = 0;
	if (close(lu->prs.fd) < 0)
		eprintf("error when closing PR file:%s\n", strerror(errno));
	lu->prs.fd = -1;
}

reqhandler_t incoming_handlers[] = {
	[PR_REQ_OPEN] = handle_open_req,
	[PR_REQ_UPDATE] = handle_update_req,
	[PR_REQ_DELETE] = handle_delete_req,
	[PR_REQ_CLOSE] = handle_close_req
};

static void *pr_thread_fn(void *arg)
{
	int nr = 1;
	struct pr_request *req;

	while (pr_thread_run) {
		pthread_mutex_lock(&incoming_lock);
		while (list_empty(&incoming_list)) {
			pthread_cond_wait(&incoming_cond, &incoming_lock);
			if (!pr_thread_run) {
				pthread_mutex_unlock(&incoming_lock);
				goto out;
			}
		}

		req = list_first_entry(&incoming_list,
				 struct pr_request, list);
		list_del(&req->list);
		pthread_mutex_unlock(&incoming_lock);

		incoming_handlers[req->type](req);

		pthread_mutex_lock(&done_lock);
		list_add_tail(&req->list, &done_list);
		pthread_mutex_unlock(&done_lock);

		if (swrite(done_fd[1], &nr, sizeof(nr)) < 0)
			eprintf("can't ack tgtd\n");
	}

out:
	pthread_exit(NULL);
}


/* user API */

int prstore_engine_init(void)
{
	int ret;

	pthread_cond_init(&incoming_cond, NULL);
	pthread_mutex_init(&incoming_lock, NULL);
	pthread_mutex_init(&done_lock, NULL);

	ret = pipe(done_fd);
	if (ret) {
		eprintf("failed to create done pipe, %m\n");
		goto destroy_cond_mutex;
	}

	ret = tgt_event_add(done_fd[0], EPOLLIN, pr_request_done, NULL);
	if (ret) {
		eprintf("failed to add epoll event\n");
		goto close_done_fd;
	}

	pr_thread_run = 1;
	ret = pthread_create(&pr_thread, NULL, pr_thread_fn, NULL);
	if (ret) {
		eprintf("failed to create prstore pr thread, %s\n", strerror(ret));
		goto event_del;
	}

	return 0;

event_del:
	tgt_event_del(done_fd[0]);
close_done_fd:
	close(done_fd[0]);
	close(done_fd[1]);
destroy_cond_mutex:
	pthread_cond_destroy(&incoming_cond);
	pthread_mutex_destroy(&incoming_lock);
	pthread_mutex_destroy(&done_lock);

	return 1;
}

static void prstore_enqueue(struct pr_request *req)
{
	pthread_mutex_lock(&incoming_lock);
	list_add_tail(&req->list, &incoming_list);
	pthread_cond_signal(&incoming_cond);
	pthread_mutex_unlock(&incoming_lock);
}

int prstore_open(struct scsi_lu *lu)
{
	struct pr_request *req;

	if (!lu->tgt->pr_dir)
		return 0;

	if (lu->prs.enable)
		/* store is already open */
		return 0;

	req = zalloc(sizeof(struct pr_request));
	if (!req) {
		eprintf("memory allocation failed\n");
		return 1;
	}

	lu->prs.enable = 1;

	req->type = PR_REQ_OPEN;
	req->open.lu = lu;

	prstore_enqueue(req);
	return 0;
}

int prstore_close(struct scsi_lu *lu)
{
	struct pr_request *req;

	if (!lu->prs.enable)
		return 0;

	req = zalloc(sizeof(struct pr_request));
	if (!req) {
		eprintf("memory allocation failed\n");
		return 1;
	}

	req->type = PR_REQ_CLOSE;
	req->close.lu = lu;

	prstore_enqueue(req);
	return 0;
}

int prstore_update(struct registration *reg, struct scsi_cmd *cmd)
{
	struct pr_request *req;

	if (!cmd->dev->prs.enable)
		return 0;

	req = zalloc(sizeof(struct pr_request));
	if (!req) {
		eprintf("memory allocation failed\n");
		return 1;
	}

	req->type = PR_REQ_UPDATE;
	req->update.reg = reg;
	req->update.cmd = cmd;

	/* must flush reg before notifying client */
	set_cmd_async(cmd);

	prstore_enqueue(req);
	return 0;
}

int prstore_delete(int slot, struct scsi_cmd *cmd)
{
	struct pr_request *req;

	if (!cmd->dev->prs.enable)
		return 0;

	req = zalloc(sizeof(struct pr_request));
	if (!req) {
		eprintf("memory allocation failed\n");
		return 1;
	}

	req->type = PR_REQ_DELETE;
	req->del.slot = slot;
	req->del.cmd = cmd;

	/* must flush reg before notifying client */
	set_cmd_async(cmd);

	prstore_enqueue(req);
	return 0;
}

void prstore_engine_deinit(void)
{
	pr_thread_run = 0;
	pthread_mutex_lock(&incoming_lock);
	pthread_cond_signal(&incoming_cond);
	pthread_mutex_unlock(&incoming_lock);
	pthread_join(pr_thread, NULL);
}
