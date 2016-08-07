/*
 * The module implements logging with advanced features like optional log
 * rotation and asynchronous writing to file.
 */
#define BUG_ON(c)				\
	if(c) {					\
	       pcs_fatal("BUG at %s:%d (%s)",	\
				 __FILE__,__LINE__,__FUNCTION__);	\
	       }							\
	

#include "xlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>


#define PCS_ERR_IO -EIO

#define PCS_PRODUCT_NAME "tgtd"
#define PCS_BUILD_VERSION "2."

static inline abs_time_t get_real_time_ms(void) {
	struct timeval tv;
	int r = gettimeofday(&tv, 0);
	BUG_ON(r);
	return (abs_time_t)tv.tv_sec*1000+tv.tv_usec/1000;
}

static inline abs_time_t get_abs_time_ms(void) {
	struct timespec ts;
	int r = clock_gettime(CLOCK_MONOTONIC,&ts);
	BUG_ON(r);
	return (abs_time_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}

static inline abs_time_t get_elapsed_time(abs_time_t now, abs_time_t old) {
	long long elapsed = now - old;
	return elapsed > 0 ? elapsed : 0;
}

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;

static int pcs_sync_open(const char * pathname, int flags, int mode, int *out_fd)
{
        int fd = -1;
        while (1) {
                fd = open(pathname, flags, mode);
                if (fd >= 0)
                        break;
                if (errno != EINTR)
                        return -errno;
        }
        *out_fd = fd;
        return 0;
}

int pcs_sync_lseek(int fd, u64 offs, int origin, u64 *new_offs)
{
        off_t offset = lseek(fd, (off_t)offs, origin);
        if (offset < 0)
                return -errno;
        if (new_offs)
                *new_offs = (u64)offset;
        return 0;
}

int pcs_sync_close(int fd)
{
        while (1) {
                int err = close(fd);
                if (!err)
                        return 0;
                if (errno != EINTR)
                        return -errno;
        }
}

/* Log level and formatting global flags */
static int __log_level = LOG_LEVEL_DEFAULT;
static __thread int __log_indent;

#define PCS_LOG_ENABLED

#ifdef PCS_LOG_ENABLED

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __WINDOWS__
#include <time.h>
#include <io.h>
#else /* __WINDOWS__ */
#include <sys/time.h>
#endif /* __WINDOWS__ */

#define _ENABLE_GZIP_COMPRESSION 1

#ifdef _ENABLE_GZIP_COMPRESSION
#define GZIP_COMPRESSION_LEVEL	"w5"
#include <zlib.h>
#endif

/*
 * The asynchronous log writer context definitions
 */ 

#define LOG_BUFF_SZ		0x100000
#define LOG_BUFF_RESERVE	0x10000
#define LOG_BUFF_THRESHOLD	(LOG_BUFF_SZ-LOG_BUFF_RESERVE)
#define LOG_BUFF_NEXT(Ind)	(((Ind) + 1) % 2)
#define LOG_BUFF_PREV(Ind)	LOG_BUFF_NEXT(Ind)

#define __str(s) #s
#define __xstr(s) __str(s)

#define	LOGGER_ERR(...) fprintf(stderr,  "ERROR (" __FILE__ ":" __xstr(__LINE__) "): " __VA_ARGS__)

struct log_buff {
	char		buff[LOG_BUFF_SZ];

	unsigned	used;	/* The number of used bytes */
	unsigned	full;	/* Set to the number of bytes if writing is pending */
};

struct log_writer {
	/* The filename */
	const char*	fname;
	/* The file descriptor */
	int	fd;
#ifdef _ENABLE_GZIP_COMPRESSION
	gzFile		gz_file;
#endif

	/* Worker thread */
	pthread_t	worker;

	/* Condition to wait on */
	pthread_cond_t	cond;
	pthread_condattr_t condattr;

	/* Current log on-disk size */
	long long 	log_size;

	/* Rotation stuff */
	long long	rotate_threshold;
	unsigned	rotate_filenum;
	int		rotate_request;

	/* Termination request */
	int		close_request;

	/* The double buffering stuff */
	int		curr;	/* Current buffer index */
	int		written;/* Last written buffer index */
	struct log_buff	b[2];

	int (*open_log)(struct log_writer* l);
	void (*write_buff)(struct log_writer* l, struct log_buff* b);
	void (*close_log)(struct log_writer* l);
	void (*reopen_log)(struct log_writer* l);
};

/* Set after client placed message with LOG_NONL flag. It indicates the client intention to continue writing
 * the log in single line. It also prevents flushing the log content. Not quite thread safe but simple enough.
 */
static int log_nonl;

/* Log writer context. The context is not allocated in case of the default stderr logging.
 * The log rotation is disabled in such case as well.
 */
static struct log_writer* logwriter;

static void init_ops_generic(struct log_writer* l);
static void init_ops_gzip(struct log_writer* l);

/* The access to the log from the client threads will be serialized */
static pthread_mutex_t loglock =
#if defined(__linux__)
	PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
	/* FIXME: MacOS doesn't support recursive locking, so logging may hang somewhere below on catching of SIGSEGV etc. */
	PTHREAD_MUTEX_INITIALIZER;
#endif
/* Prevent race between logger thread and fatal signal handler
 * for flushing the log */
static pthread_mutex_t flushlock = PTHREAD_MUTEX_INITIALIZER;
static int in_fatal_signal_handler = 0;

static inline int log_writer_active(void)
{
	return logwriter && !logwriter->close_request;
}

static inline abs_time_t lock_log(void)
{
	pthread_mutex_lock(&loglock);
	if (log_writer_active())
	{
		/* If the current buffer is full wait for write completion */
		if (logwriter->b[logwriter->curr].full) {
			abs_time_t ts1;

			ts1 = get_abs_time_ms();
			do
				pthread_cond_wait(&logwriter->cond, &loglock);
			while (logwriter->b[logwriter->curr].full);
			return get_elapsed_time(get_abs_time_ms(), ts1);
		}
	}

	return 0;
}

static inline void unlock_log(void)
{
	if (!log_nonl)
	{
		/* Flush log */
		if (log_writer_active())
		{
			struct log_buff* b = &logwriter->b[logwriter->curr];
			BUG_ON(b->full);
			if (b->used >= LOG_BUFF_THRESHOLD) {
				/* If filled switch current buffer and wake up writer */
				b->full = b->used;
				logwriter->curr = LOG_BUFF_NEXT(logwriter->curr);
				logwriter->b[logwriter->curr].used = 0;
				pthread_cond_signal(&logwriter->cond);
			}
		} else
			fflush(stderr);
	}
	pthread_mutex_unlock(&loglock);
}

/* posix file operations */
static int log_file_open(const char *filename, int flag, int pmode)
{
#ifdef __WINDOWS__
	return _open(filename, _O_BINARY | flag, pmode);
#else /* __WINDOWS__ */
	return open(filename, flag, pmode);
#endif /* __WINDOWS__ */
}

static int log_file_close(int fd)
{
#ifdef __WINDOWS__
	return _close(fd);
#else /* __WINDOWS__ */
	return close(fd);
#endif /* __WINDOWS__ */
}


static int log_file_getsize(int fd, u64* size)
{
#ifdef __WINDOWS__
	struct _stat64 st;
	if (_fstat64(fd, &st) < 0)
		return -1;
	*size = (u64)st.st_size;
#else /* __WINDOWS__ */
	struct stat st;
	if (fstat(fd, &st) < 0)
		return -errno;
	*size = st.st_size;
#endif /* __WINDOWS__ */
	return 0;
}

static int log_file_dup(int fd)
{
#ifdef __WINDOWS__
	return _dup(fd);
#else /* __WINDOWS__ */
	return dup(fd);
#endif /* __WINDOWS__ */
}

static int log_file_ftruncate(int fd, u64 offs)
{
#ifdef __WINDOWS__
	errno_t res = _chsize_s(fd, (__int64)offs);
	if (res) {
		errno = res;
		return - 1;
	}
	return 0;
#else /* __WINDOWS__ */
	int res = 0;
	while ((res = ftruncate(fd, offs)) < 0 && errno == EINTR);
	return res;
#endif /* __WINDOWS__ */
}

static s64 log_file_lseek(int fd, u64 offset, int origin)
{
#ifdef __WINDOWS__
	return _lseeki64(fd, (__int64)offset, origin);
#else /* __WINDOWS__ */
	return lseek(fd, (off_t)offset, origin);
#endif /* __WINDOWS__ */
}

static s32 log_file_read(int fd, void* buff, u32 count)
{
#ifdef __WINDOWS__
	return (s32)_read(fd, buff, count);
#else /* __WINDOWS__ */
	return (s32)read(fd, buff, count);
#endif /* __WINDOWS__ */
}

/*
 * The core log output routines
 */
static void log_printf(const char *fmt, ...) __printf(1, 2);

static void log_vprintf(const char *fmt, va_list va)
{
	int res, sz;
	struct log_buff* b;

	/* Just redirect to stderr if file writer is not allocated or already terminating*/
	if (!log_writer_active()) {
		vfprintf(stderr, fmt, va);
		return;
	}

	/* Consider current buffer */
	b = &logwriter->b[logwriter->curr];
	BUG_ON(b->full);
	sz = LOG_BUFF_SZ - b->used;
	BUG_ON(sz < 0);

	/* Output to the buffer */
	res = vsnprintf(&b->buff[b->used], sz, fmt, va);
	BUG_ON(res < 0); /* Output error */
	BUG_ON(res > sz);/* Output is truncated. 
			Do we need this bugon is not yet clear. It means that the client is writing
			more than LOG_BUFF_RESERVE in single log line. */

	/* Update used buffer space */
	b->used += res < sz ? res : sz;
}

static void log_vprintf_lvl(int level, const char *fmt, va_list va)
{
	if ((level & LOG_STDOUT) == LOG_STDOUT)
		vprintf(fmt, va);
	else
		log_vprintf(fmt, va);
}

static void log_printf(const char *fmt, ...)
{	
	va_list va;
	va_start(va, fmt);
	log_vprintf(fmt, va);
	va_end(va);
}

static void log_printf_lvl(int level, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log_vprintf_lvl(level, fmt, va);
	va_end(va);
}

/*
 * The log worker
 */

static int __open_log_file(struct log_writer* l)
{
	int fd = 0;
	int rc = 0;
	u64 size = 0;
	BUG_ON(!l->fname);
	if ((rc = pcs_sync_open(l->fname, O_WRONLY | O_CREAT | O_APPEND, 0666, &fd))) {
		pcs_log(XLOG_ERR, "failed to open log file %s : %s", l->fname, strerror(-rc));
		return -1;
	}
	if ((rc = pcs_sync_lseek(fd, 0, SEEK_END, &size)) < 0) {
		pcs_log(XLOG_ERR, "seek failed on log file %s : %s", l->fname, strerror(-rc));
		pcs_sync_close(fd);
		return -1;
	}
	l->fd = fd;
	l->log_size = size;
	return 0;
}

static int write_buff(int fd, char* buff, int sz)
{
	BUG_ON(fd < 0);
	while (sz) {
		int n = write(fd, buff, sz);
		if (n < 0) {
			return -1;
		}
		BUG_ON(n == 0);
		buff += n;
		sz -= n;
	}
	return 0;
}

static void __write_log_buff(struct log_writer* l, struct log_buff* b)
{
	int size = b->full;
	BUG_ON(!size);
	BUG_ON(size > LOG_BUFF_SZ);
	if (!write_buff(l->fd, b->buff, size)) {
		l->log_size += size;
	} else {
		fprintf(stderr, "failed to write %d bytes to %s : %s\n", size, l->fname, strerror(errno));
		fflush(stderr);
	}
}

static void log_worker_write(struct log_writer* l)
{
	for (;;)
	{
		int next_buff = LOG_BUFF_NEXT(l->written);
		struct log_buff* b = &l->b[next_buff];
		if (!b->full)
			return;

		pthread_mutex_lock(&flushlock);
		l->write_buff(l, b);
		pthread_mutex_lock(&loglock);
		b->full = 0;
		/* dev@: shit... AFAICS the same cond is used to wakeup log_worker and blocked users... can it work?... */
		pthread_cond_signal(&l->cond);
		pthread_mutex_unlock(&loglock);
		l->written = next_buff;
		pthread_mutex_unlock(&flushlock);
	}
}

static void __log_worker_close(struct log_writer* l)
{
	int res = pcs_sync_close(l->fd);
	if (res)
		pcs_log(XLOG_ERR, "failed to close log file %s : %s", l->fname, strerror(-res));
	l->fd = -1;
}

static void __log_worker_reopen(struct log_writer* l)
{
	int fd = l->fd;
	int res = l->open_log(l);
	if (res)
		return;
	res = pcs_sync_close(fd);
	if (res)
		pcs_log(XLOG_ERR, "failed to close log file %s : %s", l->fname, strerror(-res));		
}

static inline int log_worker_need_rotate(struct log_writer* l)
{
	return l->rotate_request || (l->rotate_threshold && l->log_size >= l->rotate_threshold);
}

static int log_worker_rotate(struct log_writer* l)
{
	int i, len = (int)strlen(l->fname);
	int rc = 0;
	char *src = (char*)malloc(len + 3);
	char *dst = (char*)malloc(len + 3);

	/* cleanup request first */
	l->rotate_request = 0;
	memcpy(src, l->fname, len);
	memcpy(dst, l->fname, len);
	src[len]   = dst[len]   = '.';
	src[len+1] = dst[len+1] = '0';
	src[len+2] = dst[len+2] = 0;
	/* Rename backups */
	for (i = l->rotate_filenum - 2; i >= 0; --i) {
		src[len + 1] = '0' + (char)i;
		dst[len + 1] = '0' + (char)i + 1;
		if ((rename(src, dst) < 0) && (errno != ENOENT)) {
			pcs_log(XLOG_ERR, "failed to rename log file %s -> %s : %s", src, dst, strerror(errno));
			rc = -1;
			break;
		}
	}
	/* Rename current log so it is going to be reopen */
	if (!rc && (rename(l->fname, src) < 0) && (errno != ENOENT)) {
		pcs_log(XLOG_ERR, "failed to rename log file %s -> %s : %s", l->fname, src, strerror(errno));
		rc = -1;
	}

	free(src);
	free(dst);
	return rc;
}

#define LOG_FLUSH_TOUT 5

#if defined(__LINUX__) && __GLIBC_PREREQ(2, 4) && defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK >= 0)
#define USE_MONOTONIC_CLOCK
#endif

static void* log_worker(void* arg)
{
	int res = 0;
	struct log_writer* l = arg;
	pthread_setname_np(pthread_self(), "logger");
	for (;;)
	{
		struct timespec ts;
#ifdef USE_MONOTONIC_CLOCK
		res = clock_gettime(CLOCK_MONOTONIC, &ts);
		BUG_ON(res);
#else
		struct timeval tv;
		gettimeofday(&tv, 0);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
#endif
		ts.tv_sec += LOG_FLUSH_TOUT;
		pthread_mutex_lock(&loglock);
		/* Sleeping loop */
		for (;;)
		{
			/* Check wake up conditions */
			if (l->b[0].full || l->b[1].full)
				break;
			if (l->rotate_request || l->close_request)
				break;

			res = pthread_cond_timedwait(&l->cond, &loglock, &ts);
			BUG_ON(res && res != ETIMEDOUT);
			if (res == ETIMEDOUT)
				break;
		}
		/* Flush buffer if necessary */
		if (l->b[l->curr].used && !l->b[l->curr].full)
		{
			int next_buff = LOG_BUFF_NEXT(l->curr);
			/* Enforce current buffer flushing on close or reopen or if the timeout is expired and
			 * we have the second buffer free (otherwise the client will block).
			 */
			if (l->rotate_request || l->close_request || (res == ETIMEDOUT && !l->b[next_buff].full)) {
				l->b[l->curr].full = l->b[l->curr].used;
				l->curr = next_buff;
				l->b[l->curr].used = 0;
			}
		}
		pthread_mutex_unlock(&loglock);

		/* Perform write if necessary */
		log_worker_write(l);

		/* Check need to terminate - but flush used buffers first */
		if (l->close_request && !l->b[l->curr].used && !l->b[l->curr].full)
		{
			l->close_log(l);
			break;
		}
		if (log_worker_need_rotate(l))
		{
			if (!log_worker_rotate(l))
				l->reopen_log(l);
		}
	}
	return 0;
}

#define RESERVE_LINES 0x100

/*
 * The basic log API
 */

/* Fill provided buffer with buffered log tail or returns -1 if log is not buffered. */
int pcs_log_get_tail(char* buff, unsigned* sz)
{
	struct log_buff *curr, *prev;
	unsigned sz_curr, sz_left, sz_total = 0;
	if (!logwriter)
		return -1;

	pthread_mutex_lock(&loglock);
	/*
	 * Get the most we can from 2 buffers
	 */
	curr = &logwriter->b[logwriter->curr];

	if ((sz_curr = curr->used) <= (sz_left = *sz))
	{
		sz_left -= sz_curr;
		prev = &logwriter->b[LOG_BUFF_PREV(logwriter->curr)];
		if (prev->used <= sz_left)
		{
			memcpy(buff, prev->buff, prev->used);
			sz_total += prev->used;
		}
		else {
			memcpy(buff, prev->buff + prev->used - sz_left, sz_left);
			sz_total += sz_left;
		}
		memcpy(buff + sz_total, curr->buff, sz_curr);
		sz_total += sz_curr;
	}
	else {
		memcpy(buff, curr->buff + sz_curr - sz_left, sz_left);
		sz_total += sz_left;
	}

	pthread_mutex_unlock(&loglock);

	BUG_ON(sz_total > *sz);
	*sz = sz_total;
	return 0;
}

static void log_format_time(abs_time_t ts, char* buff, unsigned sz, char *saved_time_buff, time_t *current_sec)
{
	/* if saved_time_buff and current_sec are NULL, function will each time 
	 * run localtime. else saved_time_buff will be used for filling buff, 
	 * if current_sec is equal to sec, current_sec will be updated.
	 * *current_sec must equal to 0 (first time), or value, which was returned 
	 * this function 
	 */ 
	size_t len = 0;
	time_t sec = ts / 1000;

	if (saved_time_buff && current_sec)
	{
		if (sec != *current_sec) {
			*current_sec = sec;
			len = strftime(saved_time_buff, sz, "%d-%m-%y %H:%M:%S", localtime(&sec));
			BUG_ON(!len || len >= sz);
		} else {
			len = strlen(saved_time_buff);
		}
		memcpy(buff, saved_time_buff, len);
	} else {
		len = strftime(buff, sz, "%d-%m-%y %H:%M:%S", localtime(&sec));
		BUG_ON(!len || len >= sz);
	}

	abs_time_t msec = ts - sec * 1000ULL;
	sz   -= (unsigned)len;
	buff += len;
	len = snprintf(buff, sz, ".%03lld", msec);
	BUG_ON(len >= sz);
}

void pcs_log_format_time(abs_time_t ts, char* buff, unsigned sz)
{
	log_format_time(ts, buff, sz, NULL, NULL);
}

/* Prints the log message according to the following pattern:
 * [timestamp] [indentation] [prefix: ] message [\n]
 */
static void pcs_valog(int level, const char *prefix, const char *fmt, va_list va)
{
	abs_time_t blocked_time;

	/* Trying to flush buffers after some fatal signal, don't mess around.
	 * This line is mainly necessary because gz_write_buff() calls
	 * pcs_log() in some conditions. */
	if (in_fatal_signal_handler)
		return;

	blocked_time = lock_log();

	if (!log_nonl && !(level & LOG_NOTS)) {
		char time_buff[32];
		static char saved_time_buff[32];
		static time_t current_second = 0;
		log_format_time(get_real_time_ms(), time_buff, sizeof(time_buff), saved_time_buff, &current_second);
		log_printf_lvl(level, "%s ", time_buff);
	}

	if (__log_indent && !(level & LOG_NOIND)) {
		const char indent[] = "                                                ";
		log_printf_lvl(level, "%.*s", __log_indent * 4, indent);
	}

	if (blocked_time) {
		log_printf_lvl(level, "[blocked for %llums] ", blocked_time);
	}

	if (fmt) {
		if (prefix)
			log_printf_lvl(level, "%s: ", prefix);
		log_vprintf_lvl(level, fmt, va);
	} else {
		if (prefix)
			log_printf_lvl(level, "%s", prefix);
	}

	if (!(level & LOG_NONL)) {
		log_printf_lvl(level, "\n");
		log_nonl = 0;
	} else
		log_nonl = 1;

	unlock_log();
}

int *pcs_log_lvl(void)
{
	/* On Windows delay load flow doesn't work with exported variables */
	return &__log_level;
}

int *pcs_log_indent(void)
{
	/* On Windows thread variable cannot be exported by dll
	 * See https://msdn.microsoft.com/en-us/library/40a45kxx.aspx */
	return &__log_indent;
}

static void pcs_valog_exitmsg(const char *fmt, va_list va);

void pcs_log(int level, const char *fmt, ...)
{
	va_list va;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	va_start(va, fmt);
	pcs_valog(level, NULL, fmt, va);
	va_end(va);
}

void pcs_log_hexdump(int level, const void *buf, int olen)
{
	int len = olen > 64 ? 64 : olen;
	char *str = 0, *p = 0;
	int alloc_sz;
	int i;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	alloc_sz = len * 3 + 3 + 1;	
	str = (char*)malloc(alloc_sz);
	p = str;

	*p = 0;
	for (i = 0; i < len; i++)
		p += sprintf(p, "%02x ", *((unsigned char *)buf + i));
	if (olen > len)
		p += sprintf(p, "...");
	BUG_ON(p > str + alloc_sz);
	str[alloc_sz - 1] = 0;

	pcs_log(level|LOG_NOIND, "%s", str);
	free(str);
}

void pcs_fatal(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_valog(XLOG_ERR|LOG_NOIND, "Fatal", fmt, va);
	va_end(va);
	va_start(va, fmt);
	pcs_valog_exitmsg(fmt, va);
	va_end(va);

	pcs_log_terminate();

	/* use same exit code as abort */
	exit(-134);
}

int pcs_set_logfile(const char *path)
{
	int res = 0;
	struct log_writer* l;

	/* This function may be called only once. It is expected to be called at the application startup so
	 * no protection from concurrent log access.
	 */
	BUG_ON(logwriter);

	/* Allocate context */
	l = calloc(sizeof(*l),1);

	init_ops_generic(l);

#ifdef _ENABLE_GZIP_COMPRESSION
	size_t len = strlen(path);
	if (len > 3 && !strncmp(".gz", &path[len - 3], 3))
		init_ops_gzip(l);
#endif

	/* Open log file */
	l->fname = strdup(path);
	if (l->open_log(l)) {
		free(l);
		return PCS_ERR_IO;
	}

	/* Create condition to wait on */
	res = pthread_condattr_init(&l->condattr);
	BUG_ON(res);
#ifdef USE_MONOTONIC_CLOCK
	res = pthread_condattr_setclock(&l->condattr, CLOCK_MONOTONIC);
	BUG_ON(res);
#endif
	res = pthread_cond_init(&l->cond, &l->condattr);
	BUG_ON(res);

	/* Init rotation default */
	l->rotate_filenum = DEF_LOG_ROTATE_FILENUM;
	/* No buffer yet written */
	l->written = -1;

	/* Create worker thread */
	res = pthread_create(&l->worker, NULL, log_worker, l);
	BUG_ON(res);

	/* Succeeded */
	logwriter = l;
	atexit(pcs_log_terminate);

	return 0;
}

void pcs_log_terminate(void)
{
	struct log_writer* l = NULL;

	/* Trying to flush buffers after some fatal signal, don't mess around.
	 * This line is mainly necessary because gz_write_buff() calls
	 * pcs_log() in some conditions. */
	if (in_fatal_signal_handler)
		return;

	if (!logwriter)
		return;

	pthread_mutex_lock(&loglock);
	if (log_writer_active()) {
		l = logwriter;
		logwriter->close_request = 1;
		pthread_cond_signal(&logwriter->cond);
		logwriter = NULL;
	}
	pthread_mutex_unlock(&loglock);
	if (l)
		pthread_join(l->worker, NULL);
	/* Don't free any resources since we are terminating anyway */
}

/* Returns last incomplete buffer */
static struct log_buff * flush_full_buffers(void)
{
	int next_buff;
	struct log_buff *b;

	if (log_nonl) {
		log_printf("\n");
		log_nonl = 0;
	}

	if (!logwriter)
		return NULL;

	/* lock flushlock and loglock */
	if (pthread_mutex_trylock(&flushlock)) {
		if (pthread_equal(logwriter->worker, pthread_self()))
			/* fatal error in the logwriter during
			 * flushing the log, can't recover :( */
			abort();
		/* logwriter is flushing the log, let him finish the job */
		pthread_mutex_lock(&flushlock);
	}
	pthread_mutex_lock(&loglock);

	/* flush full buffers first */
	while (1) {
		next_buff = LOG_BUFF_NEXT(logwriter->written);
		b = &logwriter->b[next_buff];
		if (!b->full)
			break;
		logwriter->write_buff(logwriter, b);
		b->full = b->used = 0;
	}

	return b;
}

static void flush_log_buffer(struct log_buff *b)
{
	if (!b)
		return;

	BUG_ON(!logwriter);
	/* flush the rest */
	b->full = b->used;
	logwriter->write_buff(logwriter, b);
}

static void describe_signal(int sig, siginfo_t *info, void *pc)
{
	char time_buff[32];
	pcs_log_format_time(get_real_time_ms(), time_buff, sizeof(time_buff));

	/* describe the signal */
	if (sig < 0 || sig >= NSIG || sys_siglist[sig] == NULL)
		log_printf("%s Got signal %d with code %d\n", time_buff, sig, info->si_code);
	else {
		log_printf("%s Got signal %d with code %d: %s", time_buff, sig, info->si_code, sys_siglist[sig]);
		switch (sig) {
			case SIGILL:
			case SIGFPE:
			case SIGSEGV:
#ifdef SIGBUS
			case SIGBUS:
#endif /* SIGBUS */
				log_printf(" at %p, invalid address is %p\n", pc, info->si_addr);
				break;
			default:
				log_printf("\n");
		}
	}
}

#ifdef __linux__
#define HAVE_REGISTER_GET_PC
static inline void *register_get_pc(ucontext_t *context)
{
#if defined(__x86_64__)
	return (void*) ((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
	return (void*) ((ucontext_t*)context)->uc_mcontext.gregs[REG_EIP];
#else
	return NULL;
#endif
}
#endif

/* This signal handler expects that it is registered using sigaction() with
 * flags field set to SA_NODEFER | SA_RESETHAND | SA_SIGINFO.
 * Due to SA_RESETHAND the signal action is restored to the default upon
 * entry to the signal handler. Then returning from the handler makes
 * execution to be restarted from the faulty instruction which will do
 * another fault, so we'll get one more signal of the same type, but now the
 * default handler will be called.
 */
void pcs_log_fatal_sighandler(int sig, siginfo_t *info, void *context)
{
	if (in_fatal_signal_handler)
		/* double fault, can't recover :( */
		return;
	in_fatal_signal_handler = 1;

	struct log_buff *b = flush_full_buffers();

	describe_signal(sig, info, register_get_pc(context));

	flush_log_buffer(b);
}



/*
 * Log rotation API
 */

void pcs_set_logrotate_size(unsigned long long size)
{
	if (!log_writer_active())
		return;
	logwriter->rotate_threshold = size;
}

void pcs_set_logrotate_filenum(unsigned int filenum)
{
	if (!log_writer_active())
		return;
	if (filenum < 1)
		filenum = 1;
	if (filenum > MAX_LOG_ROTATE_FILENUM)
		filenum = MAX_LOG_ROTATE_FILENUM;
	logwriter->rotate_filenum = filenum;
}

/* Signal handler for external rotation requests.
 * Unlike built in log rotation routine the external one works by means of renaming log files already open
 * by our application and sending us the special signal to force reopening log file without changing its name.
 * Note that the signal received can stop us with any locks acquired so just set request flag here
 * and wake up worker without locking. Don't care about lost signal since the worker will be awakened on next
 * buffer write anyway.
 */
void pcs_ext_logrotate_sighandler(int signum)
{
	/* We shouldn't call any logging functions here. loglock is recursive,
	 * but the problem is with the internal locking in localtime() */
	if (!log_writer_active())
		return;
	logwriter->rotate_request = 1;
	pthread_cond_signal(&logwriter->cond);
}

/*
 * The exit message file implements the mechanism for application to report postmortem message to the monitoring tool.
 * So it is not directly related to the log itself.
 */

static char *log_exit_msg_fname;

void pcs_set_exitmsg_file(char *path)
{
	BUG_ON(log_exit_msg_fname);
	log_exit_msg_fname = strdup(path);
}

static void pcs_valog_exitmsg(const char *fmt, va_list va)
{
	int fd = 0;
	FILE *f;
	int ret;

	if (!log_exit_msg_fname)
		return;

	/* this is to make sure that file will not be truncated */
	if ((fd = log_file_open(log_exit_msg_fname, O_WRONLY | O_CREAT, 0600)) < 0) {
		pcs_log(XLOG_ERR, "Failed to open exit message file: %s", strerror(errno));
		return;
	}

	f = fdopen(fd, "w");
	if (!f) {
		pcs_log(XLOG_ERR, "Failed to open exit message file: %s", strerror(errno));
		log_file_close(fd);
		return;
	}

	ret = vfprintf(f, fmt, va);
	if ((ret < 0) || (fputc('\0', f) == EOF))
		pcs_log(XLOG_ERR, "Failed to write exit message");

	if (fclose(f) == EOF)
		pcs_log(XLOG_ERR, "Error while closing exit message file: %s", strerror(errno));
}

void pcs_log_exitmsg(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_valog_exitmsg(fmt, va);
	va_end(va);
}

static void init_ops_generic(struct log_writer* l)
{
	l->open_log =  __open_log_file;
	l->write_buff = __write_log_buff;
	l->close_log = __log_worker_close;
	l->reopen_log = __log_worker_reopen;
}

#ifdef _ENABLE_GZIP_COMPRESSION
static void gz_close_log(struct log_writer *l)
{
	int res;
	if (!l->gz_file)
		return;

	res = gzclose(l->gz_file);
	if (res != Z_OK) {
		if (res == Z_ERRNO)
			LOGGER_ERR("failed to close compressed log file %s: %s\n", l->fname, strerror(errno));
		else
			LOGGER_ERR("failed to close compressed log file %s: %d\n", l->fname, res);
	}

	l->gz_file = NULL;
	l->fd = -1;
}

static int gz_reopen_stream(struct log_writer* l)
{
	int fd = log_file_dup((int)l->fd);
	if (fd < 0) {
		LOGGER_ERR("failed to duplicate file descriptor %s\n", strerror(errno));
		gz_close_log(l);
		return -1;
	}

	gz_close_log(l);
	if (log_file_getsize(fd, (u64*)(&l->log_size)) < 0) {
		LOGGER_ERR("failed to get file size %s\n", strerror(errno));
		gz_close_log(l);
		return -1;
	}

	l->gz_file = gzdopen(fd, GZIP_COMPRESSION_LEVEL);
	if (!l->gz_file) {
		LOGGER_ERR("failed to open zip stream\n");
		log_file_close(fd);
		return -1;
	}

	l->fd = fd;
	return 0;
}

#define HDR_FLAGS       0
#define HDR_XFLAGS      0
#ifdef __WINDOWS__
#define HDR_OSCODE      11
#else /* __WINDOWS__ */
#define HDR_OSCODE      3
#endif /* __WINDOWS__ */
#define GZ_FOOTER_LEN  8

static unsigned char hdr_signature[10] =
	{ 0x1f, 0x8b, Z_DEFLATED, HDR_FLAGS, 0, 0, 0, 0, HDR_XFLAGS, HDR_OSCODE };

static unsigned char hdr_mask[10] =
	{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff };

struct gz_footer {
	u32 crc32;
	u32 isize;
};

static struct log_writer *open_existing(int fd, u64 size, struct log_writer *log)
{
	gzFile f;
	int buf_len, err;
	u64 offs = 0;
	struct gz_footer footer;
	unsigned int *magic = (unsigned int*)hdr_signature;
	unsigned char *header = NULL, *ptr;
	unsigned char *buf;
	struct log_writer *rc = NULL;

	if (size <= (GZ_FOOTER_LEN + sizeof(hdr_signature))) {
		if ((err = log_file_ftruncate(fd, (u64)0)) < 0) {
			LOGGER_ERR("ftruncate failed - %s\n", strerror(errno));
			return NULL;
		}

		if (log_file_lseek(fd, 0, SEEK_END) < 0) {
			LOGGER_ERR("failed to seek to the end of file - %s\n", strerror(errno));
			return NULL;
		}

		f = gzdopen(fd, GZIP_COMPRESSION_LEVEL);
		if (!f) {
			LOGGER_ERR("failed to open zip stream for write\n");
			return NULL;
		}

		log->fd = fd;
		log->gz_file = f;
		log->log_size = 0;
		return log;
	}

	buf = malloc(LOG_BUFF_SZ);

	if (size > LOG_BUFF_SZ)
		offs = size - LOG_BUFF_SZ;

	/* read last LOG_BUFF_SZ of log */
	if (log_file_lseek(fd, offs, SEEK_SET) < 0) {
		LOGGER_ERR("failed to seek - %s\n", strerror(errno));
		goto _cleanup;
	}

	buf_len = log_file_read(fd, buf, LOG_BUFF_SZ);
	if (buf_len < 0) {
		LOGGER_ERR("can't read tail of log - %s\n", strerror(errno));
		goto _cleanup;
	}

	BUG_ON(sizeof(footer) != GZ_FOOTER_LEN);
	memcpy(&footer, buf + buf_len - GZ_FOOTER_LEN, GZ_FOOTER_LEN);

	/* try find gzip header in log's tail */
	ptr = (buf + buf_len) - sizeof(hdr_signature);
	while(ptr >= buf && !header) {
		unsigned int i, *val = (unsigned int *)ptr;
		if (*val != *magic) {
			ptr--;
			continue;
		}

		/* validate full header */
		for(i=0; i<sizeof(hdr_signature); ++i) {
			if ((ptr[i] & hdr_mask[i]) != hdr_signature[i])
				break;
		}

		if (i < sizeof(hdr_signature)) {
			ptr -= sizeof(*magic);
			continue;
		}

		header = ptr;
		offs = offs + (header - buf);
		BUG_ON(offs > size);
		s64 out_offs = log_file_lseek(fd, offs, SEEK_SET);
		if (out_offs < 0 || (u64)out_offs != offs) {
			LOGGER_ERR("lseek failed - %s\n", strerror(errno));
			goto _cleanup;
		}
	}

	if (!header) {
		LOGGER_ERR("Unable find gzip header in log's tail\n");
		goto _cleanup;
	}

	ptr = buf; buf_len = 0;
	/* try decompress last chunk */
	f = gzdopen(fd, "r");
	if (f) {
		while((err = gzread(f, ptr, LOG_BUFF_SZ - buf_len)) > 0) {
			ptr += err;
			buf_len += err;
		}

		/* close zip stream */
		fd = log_file_dup(fd); err = errno; gzclose(f);
		if (fd < 0) {
			LOGGER_ERR("failed to duplicate file descriptor %s\n", strerror(err));
			goto _cleanup;
		}
	}

	/* for correctly closed .gz file footer.isize must be equal to buf_len */
	if (!f || (u32)buf_len != footer.isize) {
		/* set offset to last header */
		BUG_ON(offs > size);
		if ((err = log_file_ftruncate(fd, offs)) < 0) {
			LOGGER_ERR("ftruncate failed - %s\n", strerror(errno));
			log_file_close(fd);
			goto _cleanup;
		}

		if (log_file_lseek(fd, 0, SEEK_END) < 0) {
			LOGGER_ERR("failed to seek to the end of file - %s\n", strerror(errno));
			goto _cleanup;
		}
	}

	if ((err = log_file_getsize(fd, &size)) < 0) {
		LOGGER_ERR("failed to get file size - %s\n", strerror(errno));
		log_file_close(fd);
		goto _cleanup;
	}

	f = gzdopen(fd, GZIP_COMPRESSION_LEVEL);
	if (!f) {
		LOGGER_ERR("failed to open zip stream for write [2]\n");
		log_file_close(fd);
		goto _cleanup;
	}

	log->fd = fd;
	log->gz_file = f;
	log->log_size = size;

	if ((u32)buf_len != footer.isize && buf_len > 0) {
		/* rewrite last chunk */
		err = gzwrite(log->gz_file, buf, buf_len);
		if (!err) {
			LOGGER_ERR("gzwrite failed - %s, %d\n", gzerror(log->gz_file, &err), err);
			gz_close_log(log);
			goto _cleanup;
		}

		BUG_ON(err < 0);
		gzputs(f, "\n------ end of restored log ------\n");
		if (gz_reopen_stream(log)) {
			LOGGER_ERR("Unable reopen zip stream\n");
			gz_close_log(log);
			goto _cleanup;
		}
	}
	rc = log;

_cleanup:
	free(buf);
	return rc;
}

static int gz_open_log(struct log_writer *l)
{
	int fd = 0;
	u64 size = 0;
	gzFile fi;

	BUG_ON(!l->fname);
	fd = log_file_open(l->fname, O_RDWR, 0);
	if (fd < 0) {
		if (errno == ENOENT)
			fd = log_file_open(l->fname, O_RDWR|O_CREAT, 0666);

		if (fd < 0) {
			LOGGER_ERR("failed to open log file %s : %s\n", l->fname, strerror(errno));
			return -1;
		}

		fi = gzdopen(fd, GZIP_COMPRESSION_LEVEL);
		if (!fi) {
			LOGGER_ERR("failed to open zip stream\n");
			log_file_close(fd);
			return -1;
		}
		l->log_size = 0;
		l->fd = fd;
		l->gz_file = fi;
	} else {
		if (log_file_getsize(fd, &size) < 0) {
			LOGGER_ERR("can't stat file %s - %s\n", l->fname, strerror(errno));
			log_file_close(fd);
			return -1;
		}
		if (!open_existing(fd, size, l)) {
			log_file_close(fd);
			return -1;
		}
	}

	return 0;
}

static void gz_write_buff(struct log_writer* l, struct log_buff* b)
{
	int size = b->full;
	char *ptr = b->buff;
	BUG_ON(!size);
	BUG_ON(size > LOG_BUFF_SZ);

	if (!l->gz_file) {
		if (gz_open_log(l) < 0)
			return;
	}

	while (size > 0) {
		int rc = gzwrite(l->gz_file, ptr, size);
		if (!rc) {
			int err;
			const char *errmsg;
			errmsg = gzerror(l->gz_file, &err);
			LOGGER_ERR("gzwrite failed - %s, %d\n", errmsg, err);
			gzclearerr(l->gz_file);
			return;
		}
	
		BUG_ON(rc < 0);

		ptr += rc;
		size -= rc;
	}

	(void)gz_reopen_stream(l);
}

static void gz_reopen_log(struct log_writer* l)
{
	int fd = 0;
	gzFile fi;

	gz_close_log(l);

	fd = log_file_open(l->fname, O_RDWR|O_CREAT, 0666);
	if (fd < 0) {
		LOGGER_ERR("Unable open file %s - %s\n", l->fname, strerror(errno));
		return;
	}

	fi = gzdopen(fd, GZIP_COMPRESSION_LEVEL);
	if (!fi) {
		LOGGER_ERR("gzdopen failed\n");
		log_file_close(fd);
		return;
	}

	l->fd = fd;
	l->gz_file = fi;
	l->log_size = 0;
}

static void init_ops_gzip(struct log_writer* l)
{
	l->open_log = gz_open_log;
	l->write_buff = gz_write_buff;
	l->close_log = gz_close_log;
	l->reopen_log = gz_reopen_log;
}

#endif	/* _ENABLE_GZIP_COMPRESSION */

#endif /* PCS_LOG_ENABLED */

void pcs_err(const char *msg, const char *file, int line, const char *func)
{
	pcs_log(XLOG_ERR | LOG_NOIND, "%s at %s:%d/%s()", msg, file, line, func);
#ifndef DEBUG
	pcs_log(XLOG_ERR | LOG_NOIND, PCS_PRODUCT_NAME" version: "TGT_VERSION);
#else
	pcs_log(XLOG_ERR | LOG_NOIND, PCS_PRODUCT_NAME" version: "TGT_VERSION" (Debug)");
#endif
	pcs_log_terminate();

	abort();
}
