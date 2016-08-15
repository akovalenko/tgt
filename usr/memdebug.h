#ifndef H_MEMDEBUG_INCLUDED
#define H_MEMDEBUG_INCLUDED

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>

struct memdebug_info {
	const char *file;
	int line;
	pthread_mutex_t lock;
	size_t total_bytes, total_blocks, used_bytes, used_blocks;
	struct memdebug_info *next;
};

void* memdebug_memalign(struct memdebug_info *mi, size_t alignment, size_t size);
int memdebug_posixy_memalign(struct memdebug_info *mi, void **memptr, size_t alignment, size_t size);

void* memdebug_malloc(struct memdebug_info *mi, size_t size);
void* memdebug_valloc(struct memdebug_info *mi, size_t size);
void* memdebug_zmalloc(struct memdebug_info *mi, size_t size);
void* memdebug_calloc(struct memdebug_info *mi, size_t nmemb, size_t size);
void* memdebug_realloc(struct memdebug_info *mi, void* ptr, size_t size);
void memdebug_free(struct memdebug_info *mi, void* ptr);
char* memdebug_strdup(struct memdebug_info *mi, const char* str);
char* memdebug_strndup(struct memdebug_info *mi, const char* str, size_t n);
int memdebug_vasprintf(struct memdebug_info *mi, char **strp, const char* fmt, va_list ap);
int memdebug_asprintf(struct memdebug_info *mi, char **strp, const char* fmt, ...);
void memdebug_notice(struct memdebug_info *mi);
void memdebug_map(void (*fun)(struct memdebug_info *item, void* arg), void *arg);

void memdebug_dump_stats(void (*dumper)(const char *string, void* arg), void *arg);
void MD_DUMPER_PREFIXED_PRINTF(const char *out, void *arg);
void MD_DUMPER_FILEPTR(const char *out, void *arg);

void memdebug_set_enabled(bool arg);

static inline bool memdebug_info_has_alloc(struct memdebug_info *mi) {
	return !!mi->total_blocks;
}

static inline bool memdebug_info_has_free(struct memdebug_info *mi) {
	return (!mi->total_blocks && mi->used_blocks);
}

/* routine routines */
#ifndef MEMDEBUG_HOOK

#define md_memalign memalign
#define md_posix_memalign posix_memalign
#define md_valloc valloc
#define md_malloc malloc
#define md_zmalloc(size) calloc(size,1u)
#define md_calloc calloc
#define md_realloc realloc
#define md_free free
#define md_strdup strdup
#define md_strndup strndup
#define md_vasprintf vasprintf
#define md_asprintf asprintf

#else  /* def MEMDEBUG_HOOK */

#define MD_TRACE(func, ...)						\
	({								\
		static struct memdebug_info tr = {			\
			__FILE__,__LINE__,				\
			PTHREAD_MUTEX_INITIALIZER};			\
		void __attribute__((constructor)) _lnk(void) {		\
			memdebug_notice(&tr);				\
		}							\
		func (&tr ,__VA_ARGS__);				\
	})

#define md_memalign(align,size) MD_TRACE(memdebug_memalign,align,size)
#define md_posix_memalign(ptr,align,size) MD_TRACE(memdebug_posix_memalign,ptr,align,size)
#define md_valloc(size) MD_TRACE(memdebug_valloc,size)
#define md_malloc(size) MD_TRACE(memdebug_malloc,size)
#define md_zmalloc(size) MD_TRACE(memdebug_zmalloc,size)
#define md_calloc(nmemb,size) MD_TRACE(memdebug_calloc,nmemb,size)
#define md_realloc(ptr,size) MD_TRACE(memdebug_realloc,ptr,size)
#define md_free(ptr) MD_TRACE(memdebug_free,ptr)
#define md_strdup(ptr) MD_TRACE(memdebug_strdup,ptr)
#define md_strndup(ptr,n) MD_TRACE(memdebug_strndup,ptr,n)
#define md_vasprintf(pptr,fmt,ap) MD_TRACE(memdebug_vasprintf,fmt,ap)
#define md_asprintf(pptr,fmt,...) MD_TRACE(memdebug_asprintf,pptr,fmt,__VA_ARGS__)

#endif /* MEMDEBUG_HOOK */

#endif	/* H_MEMDEBUG_INCLUDED */
