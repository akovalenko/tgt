#include "memdebug.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include "memdebug.h"
#include <stdio.h>

#include <pthread.h>
#include <unistd.h>
#include <errno.h>

struct memdebug_info;

/* Magic values for verification: BH_MAGIC for block header, BF_MAGIC
 * for block footer (additional room, right after user data, helping
 * detection of continuous memory corruption) */
#define BH_MAGIC 0xE2E4E7E5u
#define BF_MAGIC 0xE7E5E2E4u

/* Additional block header for head data */
struct block_header {
	/* BH_MAGIC */
	unsigned magic;
	/* requested alignment (1 for "natural" malloc alignment) */
	size_t alignment;
	/* malloc return value + prefix = &block_header */
	size_t prefix;
	/* requested userdata size (adjusted on realloc) */
	size_t requested;
	/* initially allocated by ...file:line */
	struct memdebug_info *mi;
};

/* Footer to be written right after user data. __packed__ to detect
 * off-by-one overwrites */

struct block_footer  {
	unsigned magic;
} __attribute__((packed));

static inline struct block_header *header_of(void* userdata)
{
	struct block_header *after_bh = userdata;
	return after_bh-1;
}

static inline void* origin_of(void* userdata) {
	struct block_header *bh = header_of(userdata);
	return (char*)bh - bh->prefix;
}

static inline struct block_footer *footer_of(void* userdata)
{
	return (void*)((char*)userdata + header_of(userdata)->requested);
}

static inline void* alignpointer(void* ptr, size_t alignment) {
	char *chptr = ptr;
	size_t mask = alignment - 1;
	size_t delta = (1+~((size_t)ptr))&mask;
	/* alignment should be a power of 2 */
	assert((alignment & mask) == 0);
	return chptr + delta;
}

static bool memdebug_enabled;

/* Update memdebug_info counters for each alloc/realloc/free. */
static inline void account(struct memdebug_info *mi,
			   size_t morebytes, size_t moreblocks,
			   size_t dbytes, size_t dblocks) {
	if (memdebug_enabled) {
		pthread_mutex_lock(&mi->lock);
		mi->total_bytes += morebytes;
		mi->total_blocks += moreblocks;
		mi->used_bytes += dbytes;
		mi->used_blocks += dblocks;
		pthread_mutex_unlock(&mi->lock);
	}
}

/* Fundamental */
void* memdebug_umemalign(struct memdebug_info *mi, size_t alignment, size_t size, bool zerop) {
	size_t adjsize = size + sizeof (struct block_header) + alignment - 1
		+ sizeof (struct block_footer);
	void *ptr = zerop? calloc(adjsize,1) : malloc(adjsize);
	char *userdata = ptr;
	struct block_header *bh;

	if (!ptr)
		return NULL;
	/* Nearest point of alignment after ptr+bh  */
	userdata = alignpointer(userdata + sizeof(struct block_header),alignment);
	bh = (struct block_header*)(userdata-sizeof(struct block_header));
	bh->magic = BH_MAGIC;
	bh->prefix = (char*)bh-(char*)ptr;
	bh->alignment = alignment;
	bh->requested = size;
	bh->mi = mi;
	footer_of(userdata)->magic = BF_MAGIC;
	account(bh->mi,size,1u,size,1u);
	
	return userdata;
}
void* memdebug_memalign(struct memdebug_info *mi, size_t alignment, size_t size)
{
	return memdebug_umemalign(mi,alignment,size,0);
}
int memdebug_posix_memalign(struct memdebug_info *mi, void **memptr, size_t alignment, size_t size)
{
	void *mem;
	if (alignment % (sizeof(void*))||(alignment & (alignment-1))) {
		return EINVAL;
	}
	mem = memdebug_umemalign(mi,alignment,size,0);
	if (!mem) {
		return ENOMEM;
	}
	*memptr = mem;
	return 0;
}

void* memdebug_valloc(struct memdebug_info *mi, size_t size) {
	return memdebug_memalign(mi,sysconf(_SC_PAGE_SIZE),size);
}

void* memdebug_malloc(struct memdebug_info *mi, size_t size) {
	
	return memdebug_umemalign(mi,1,size,false);
}

void* memdebug_zmalloc(struct memdebug_info *mi, size_t size) {
	return memdebug_umemalign(mi,1,size,true);
}

void* memdebug_calloc(struct memdebug_info *mi, size_t nmemb, size_t size) {
	size_t wholesize = nmemb*size;
	assert(size==0 || wholesize/size==nmemb);
	return memdebug_umemalign(mi,1,wholesize,true);
}

void* memdebug_realloc(struct memdebug_info *mi, void* ptr, size_t size) {
	if (!ptr) {
		return memdebug_malloc(mi,size);
	} else {
		struct block_header *bh = header_of(ptr);
		void *mptr = origin_of(ptr);
		assert(bh->magic == BH_MAGIC);
		assert(bh->alignment == 1);
		mptr = realloc(mptr, size+bh->prefix);
		if (mptr) {
			/* adjust total (?) and used bytes */
			account(mi,size - bh->requested, 0, size - bh->requested, 0);
			bh->requested = size;
			/* New footer */
			footer_of(mptr)->magic = BF_MAGIC;
		}
		return mptr ? (char*)mptr+bh->prefix : NULL;
	}
}

void memdebug_free(struct memdebug_info *mi, void* ptr) {
	if (ptr) {
		struct block_header *bh = header_of(ptr);
		struct block_footer *bf = footer_of(ptr);
		void *mptr = origin_of(ptr);
		assert(bh->magic == BH_MAGIC);
		assert(bf->magic == BF_MAGIC);
		/* printf("Free @%p (%zd) origin %p header %p footer %p\n ", */
		/*        ptr,bh->requested,mptr,header_of(ptr),footer_of(ptr)); */
		account(bh->mi,0u,0u,-bh->requested,-1);
		/* account at free */
		account(mi,0u,0u,bh->requested,1);
		free(mptr);
	}
}


char* memdebug_strdup(struct memdebug_info *mi, const char* str) {
	size_t size = strlen(str)+1;
	char *newptr = memdebug_malloc(mi,size);
	if (!newptr)
		return NULL;		/* ENOMEM? */
	memcpy(newptr, str, size);
	return newptr;
}

char* memdebug_strndup(struct memdebug_info *mi, const char* str, size_t n) {
	size_t size=0, allocsize;
	char* newptr;
	while (size<n && str[size])
		++size;
	if (size==0)
		return NULL;
	/* size=n if we found no NUL or it's just rigth at n
	   we allocate size on the latter case
	 */
	allocsize=size+(str[n]?0:1);
	newptr = memdebug_malloc(mi,allocsize);
	if (!newptr)
		return NULL;		/* ENOMEM? */
	memcpy(newptr, str, size);
	newptr[allocsize-1]=0;

	return newptr;
}

#define ASPRINTF_EXPECT_LENGTH 128 

int memdebug_vasprintf(struct memdebug_info *mi, char **strp, const char* fmt, va_list ap) {
	char buf[ASPRINTF_EXPECT_LENGTH];
	char *result = NULL;
	int length, rlength; 
	va_list ap2;
	
	va_copy(ap2,ap);
	length = vsnprintf(buf,sizeof buf,fmt,ap);
	if (length < 0)
		return length;
	
	if (length < sizeof buf) {
		/* full string there */
		result = memdebug_strdup(mi,buf);
		rlength = length;
	} else {
		/* realloc */
		result = memdebug_malloc(mi,length+1);
		rlength = vsnprintf(result,length+1,fmt,ap2);
		if (rlength < 0) {
			free(result);
			result = NULL;
		} else {
			assert(length == rlength);
		}
	}
	va_end(ap);
	va_end(ap2);
	
	if (result)
		*strp = result;
	return rlength;
}

int memdebug_asprintf(struct memdebug_info *mi, char **strp, const char* fmt, ...) {
	int result;
	va_list ap;
	va_start(ap,fmt);
	result = memdebug_vasprintf(mi,strp,fmt,ap);
	va_end(ap);
	return result;
}

static struct memdebug_info *infos;

void memdebug_notice(struct memdebug_info *mi) {
	mi->next = infos;
	infos = mi;
};

void memdebug_map(void (*fun)(struct memdebug_info *item, void* arg), void *arg) {
	struct memdebug_info *mi = infos;
	struct memdebug_info themi;
	while (mi) {
		pthread_mutex_lock(&mi->lock);
		themi = *mi;
		pthread_mutex_unlock(&mi->lock);
		fun(&themi,arg);
		mi = mi->next;
	}
}

struct dumping {
	char *buffer;
	void (*dumper)(const char *string, void* arg);
	void *arg;
	int fnwidth;
	size_t total_bytes, total_blocks, used_bytes, used_blocks;
};

static int max_file_length(void) {
	static int cached = 0;
	int counted = 0;
	if (cached)
		return cached;
	
	struct memdebug_info *mi = infos;
	while (mi) {
		int length = strlen(mi->file);
		counted = counted < length ?  length : counted;
		mi = mi->next;
	}
	cached = counted;
	return counted;
}

void memdebug_dumper_printf_prefix(const char *out, void *arg) {
	const char* prefix = arg;
	if (!prefix) prefix = "";
	printf("%s%s\n",prefix,out);
}

void MD_DUMPER_PREFIXED_PRINTF(const char *out, void *arg) {
	const char* prefix = arg;
	if (!prefix) prefix = "";
	printf("%s%s\n",prefix,out);
}

void MD_DUMPER_FILEPTR(const char *out, void *arg) {
	FILE* f = arg;
	fprintf(f,"%s\n",out);
}

#define LINE_SIZE 128

static void memdebug_dump_line(struct memdebug_info *mi, void* arg) {
	struct dumping *d = arg;
	if (memdebug_info_has_alloc(mi)) {
		snprintf(d->buffer, LINE_SIZE-1,
			 "%*s:%-6d | USED: %zd bytes in %zd blocks, TOTAL: %zd bytes in %zd blocks",
			 d->fnwidth,mi->file,mi->line,
			 mi->used_bytes,mi->used_blocks, mi->total_bytes, mi->total_blocks);
		d->dumper(d->buffer,d->arg);
	}
}

void memdebug_dump_stats(void (*dumper)(const char *string, void* arg), void *arg)
{
	char line[LINE_SIZE]={0};
	struct dumping d = {line, dumper, arg, max_file_length()};
	memdebug_map(memdebug_dump_line, &d);
}

void memdebug_set_enabled(bool arg) {
	memdebug_enabled = arg;
}
