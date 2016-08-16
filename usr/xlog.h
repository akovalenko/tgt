#ifndef __PCSLOG_H__
#define __PCSLOG_H__

#ifndef likely
#define likely(x) __builtin_expect(!!(x),1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x),0)
#endif
#define __printf(x,y) __attribute__((format(printf, x, y)))
#define __noreturn __attribute__((noreturn))

typedef unsigned long long abs_time_t;

/*
 * The module implements logging with advanced features like optional log
 * rotation and asynchronous writing to file.
 */

/*
 * Log level values and flags
 */
#define XLOG_ERR		0
#define XLOG_WARN	1
#define XLOG_INFO	2
#define XLOG_DEBUG	4
/* The high debug levels are used for dumping the system state */
#define XLOG_DEBUG2	5
#define XLOG_DEBUG3	6
/* Tracing levels */
#define XLOG_TRACE	7
#define XLOG_DEBUG4	8
#define XLOG_DEBUG5	9
#define XLOG_LEVEL_MAX	XLOG_DEBUG5

/* The LOG_TRACE represents the 'production' level tracing which may be enabled by default.
 * So the next level is 'debug' level tracing
 */
#define XLOG_DTRACE XLOG_DEBUG4

/* Default log level */
#define LOG_LEVEL_DEFAULT XLOG_WARN

/* Default log level for server (non-interactive) components */
#define LOG_LEVEL_SRV_DEFAULT XLOG_TRACE

#define LOG_LEVEL_MASK	0x0FF
#define LOG_NONL	0x100	/* no default \n at the end */
#define LOG_NOIND	0x200	/* no indentation */
#define LOG_NOTS	0x400	/* no timestamp */
#define LOG_STDOUT	(0x800 | LOG_NOTS)	/* trace to stdout */

/* Global variables */
int *pcs_log_lvl(void);
#define pcs_log_level (*pcs_log_lvl())

int *pcs_log_indent(void);
#define log_indent (*pcs_log_indent())

/* Returns true if pcs_log_level is not enough to print messages with a given verbosity level */
static inline int pcs_log_quiet(int level)
{
	return likely((pcs_log_level & LOG_LEVEL_MASK) < level);
}

/*
 * The basic log API
 */

/* Log message formatting routines */
void pcs_log(int level, const char *fmt, ...) __printf(2, 3);
void pcs_log_hexdump(int level, const void *buf, int len);

struct trace_point;
void pcs_trace(int level, struct trace_point* tp, const char *fmt, ...) __printf(3, 4);

/* Debug routines */
void __noreturn pcs_err(const char *msg, const char *file, int line, const char *func);
void __noreturn pcs_fatal(const char *fmt, ...) __printf(1,2);
void show_trace(void);

/* Fill buffer with formatted time. */
void pcs_log_format_time(abs_time_t ts, char* buff, unsigned sz);

/* Direct log output to the file and switch to buffered asynchronous writing scheme. */
int pcs_set_logfile(const char * path);
/* Write buffered data data to disk and terminate writer thread. */
void pcs_log_terminate(void);

/* Fill provided buffer with buffered log tail or returns -1 if log is not buffered. */
int pcs_log_get_tail(char* buff, unsigned* sz);

#if defined(__LINUX__) || defined(__MAC__)
#include <signal.h>

/* Terminate log on fatal signals gracefully */
void pcs_log_fatal_sighandler(int sig, siginfo_t *info, void *context);
#elif defined(__WINDOWS__)
LONG __stdcall pcs_log_fatal_sighandler(EXCEPTION_POINTERS *ptrs);
#endif

/* Asynchronous interface for system log */
struct pcs_syslog_logger;
struct pcs_process;

void pcs_syslog(struct pcs_syslog_logger *l, int priority, const char *fmt, ...) __printf(3, 4);
int pcs_syslog_open(struct pcs_process *proc, const char *name, struct pcs_syslog_logger **logger);
void pcs_syslog_close(struct pcs_syslog_logger *l);

/*
 * Log rotation support (buffered writing only).
 */
#define DEF_LOG_ROTATE_FILENUM 5
#define MAX_LOG_ROTATE_FILENUM 10

void pcs_set_logrotate_size(unsigned long long size);
void pcs_set_logrotate_filenum(unsigned int filenum);
void pcs_ext_logrotate_sighandler(int signum);

/* The exit message file may optionally contain the postmortem message from application to management tools. */
void pcs_set_exitmsg_file(char *path);
void pcs_log_exitmsg(const char *fmt, ...) __printf(1,2);

#endif /* __PCSLOG_H__ */
