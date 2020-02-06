#include <unistd.h>
#include <errno.h>
#include <string.h>

// #ifdef memcpy
// #undef memcpy
// #endif

#define powerof2(x) ((((x)-1) & (x)) == 0)

#define __malloc __libc_malloc
#define __free __libc_free
#define __calloc __libc_calloc
#define __realloc __libc_realloc
#define __aligned_alloc __libc_aligned_alloc
#define __memalign __libc_memalign
#define __pvalloc __libc_pvalloc
#define __valloc __libc_valloc

/* static lib declarations */
void dang_init_heapobj(unsigned long, unsigned long);
void dang_freeptr(unsigned long);

/* hook to metadata */
static inline void alloc_hook(char* ptr, size_t size) {
    dang_init_heapobj((unsigned long) ptr, (unsigned long) size);
}

static inline void dealloc_hook(char* ptr) {
    dang_freeptr((unsigned long) ptr);
}

/* libc declarations */
void *__libc_malloc(size_t);
void __libc_free(void *);
void *__libc_calloc(size_t, size_t);
void *__libc_realloc(void *, size_t);
void *__libc_memalign(size_t, size_t);
void *__libc_aligned_alloc(size_t, size_t);
void *__libc_valloc(size_t);
void *__libc_pvalloc(size_t);
int __posix_memalign(void **, size_t, size_t);

size_t malloc_usable_size(void *ptr);

/* overload libc malloc */
void *malloc(size_t size) {
    void *res = __malloc(size);
    alloc_hook((char *)res, size);
    return res;
}

void *calloc(size_t num, size_t size) {
    void *res = __calloc(num, size);
    alloc_hook((char *)res, num * size);
    return res;
}

void free(void *ptr) {
    // check_double_free(ptr);
    __free(ptr);
    dealloc_hook((char *)ptr);
}

void *realloc(void *old_ptr, size_t new_size) {
    void *res = NULL;
#if 0
    res = __realloc(old_ptr, new_size);
    realloc_hook((char*)old_ptr, (char*)res, new_size);
#else
    if (new_size == 0) {
        __free(old_ptr);
        dealloc_hook((char *)old_ptr);
        res = NULL;
    } else if (!old_ptr) {
        res = __malloc(new_size);
        alloc_hook((char *)res, new_size);
    } else {
        size_t old_size = malloc_usable_size(old_ptr);
        res = __malloc(new_size);
        alloc_hook((char *)res, new_size);
        if (res) {
            memcpy(res, old_ptr, (new_size > old_size) ? old_size : new_size);
            __free(old_ptr);
            dealloc_hook((char *)old_ptr);
        }
    }
#endif
    return res;
}

void *memalign(size_t alignment, size_t bytes) {
    void *res = __memalign(alignment, bytes);
    //msg("[memalign]");
    alloc_hook((char *)res, bytes);
    return res;
}

void *aligned_alloc(size_t alignment, size_t bytes) {
    void *res = __memalign(alignment, bytes);
    //msg("[aligned_alloc]");
    alloc_hook((char *)res, bytes);
    return res;
}

void *valloc(size_t size) {
    void *res = __valloc(size);
    //msg("[valloc]");
    alloc_hook((char *)res, size);
    return res;
}

void *pvalloc(size_t size) {
    void *res = __pvalloc(size);
    //msg("[pvalloc]");
    alloc_hook((char *)res, size);
    return res;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    void *mem;
    //msg("[posix_memalign]");
    // Test whether the SIZE argument is valid.  It must be a power of
    // two multiple of sizeof (void *).
    if (alignment % sizeof(void *) != 0 ||
        !powerof2(alignment / sizeof(void *)) || alignment == 0)
        return EINVAL;
    mem = __memalign(alignment, size);
    if (mem != NULL) {
        *memptr = mem;
        alloc_hook((char *)mem, size);
        return 0;
    }
    return ENOMEM;
}
// #define memcpy __memcpy
