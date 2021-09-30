#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "my_mmap.h"
#include "mem_alloc.h"
#include "mem_alloc_types.h"

#define ULONG(x) ((long unsigned int)(x))
#define FBLOCK_SIZE (sizeof(struct mem_free_block))
#define ABLOCK_SIZE (sizeof(struct mem_used_block))

// Pointer to the beginning of the memory region to manage.
void *heap_start;

// Pointer to the first free block in the heap.
mem_free_block_t *first_free;

/* -------------------------------------------------------------------------- */
#if defined(FIRST_FIT)

void *memory_alloc_policy(size_t size)
{

    mem_free_block_t *previous, *current;

    current = first_free;
    previous = current;
    while (current != NULL) {
        if (current->size > size) {
            mem_free_block_t *new_free_block;
            new_free_block = (void *) current + ABLOCK_SIZE + size;
            new_free_block->size = current->size - size - FBLOCK_SIZE;
            new_free_block->next = current->next;
            if (current->next == NULL)
                first_free = new_free_block;
            else {
                previous->next = new_free_block;
                current->next = NULL;
            }
            return (void *) current;
        }
        if (current->size == size) {
            if (current->next == NULL)
                first_free = NULL;
            else
                previous->next = current->next;
            return (void *) current;
        }
        previous = current;
        current = current->next;
    }
    return NULL;

}

#elif defined(BEST_FIT)

/* TODO: code specific to the BEST FIT allocation policy can be
* inserted here */

#elif defined(NEXT_FIT)

/* TODO: code specific to the NEXT FIT allocation policy can be
* inserted here */

#endif
/* -------------------------------------------------------------------------- */

void run_at_exit(void)
{
fprintf(stderr,"YEAH B-)\n");

/* TODO: insert your code here */
}




void memory_init(void)
{

    atexit(run_at_exit);
    heap_start = my_mmap(MEMORY_SIZE);
    first_free = (mem_free_block_t *) heap_start;
    first_free->size = MEMORY_SIZE - FBLOCK_SIZE;
    first_free->next = NULL;
    return;

}

void *memory_alloc(size_t size)
{

    mem_used_block_t *allocated_block;

    allocated_block = (mem_used_block_t *) memory_alloc_policy(size);
    if (allocated_block == NULL)
        exit(0);
    allocated_block->size = size;
    print_alloc_info((void *) allocated_block + ABLOCK_SIZE, size);
    return (void *) allocated_block + ABLOCK_SIZE;

}

void memory_free(void *p)
{

    /* TODO: insert your code here */
    void *size_address = p - ABLOCK_SIZE;
    size_t size = *(size_t *) size_address;

    mem_free_block_t *freed_block, *current_free;
    freed_block = (mem_free_block_t *) size_address;

    current_free = first_free;
    while (current_free != NULL) {
        if ((void *) freed_block + FBLOCK_SIZE + size == (void *) current_free) {
            freed_block->next = current_free;
            if (current_free->next == first_free) {
                first_free = freed_block;
                first_free->size += (FBLOCK_SIZE + size);
            } else
                freed_block->size = size + FBLOCK_SIZE + current_free->size;
        } else if ((void *) current_free + FBLOCK_SIZE + current_free->size ==
                    (void *) freed_block) {
            current_free->next = freed_block;
            current_free->size += (FBLOCK_SIZE + size);
        } else if ((void *) freed_block + FBLOCK_SIZE + size < (void *) current_free) {
            freed_block->next = current_free;
            freed_block->size = size;
        }
        current_free = current_free->next;
    }
    print_free_info(p);
    /* TODO : don't forget to call the function print_free_info()
    * appropriately */

}

size_t memory_get_allocated_block_size(void *addr)
{

/* TODO: insert your code here */

return 0;
}


void print_mem_state(void)
{

    mem_free_block_t *i;

    i = first_free;
    while (i != NULL) {
        fprintf(stderr, "BLOCK at %lX (%ld bytes) ->\n", ULONG(i), i->size);
        i = i->next;
    }

}


void print_info(void)
{

    fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", ULONG(heap_start),
        ULONG((char *) heap_start + MEMORY_SIZE), ULONG(MEMORY_SIZE));

}

void print_free_info(void *addr)
{

    if (addr) {
        fprintf(stderr, "FREE  at : %lu \n",
            ULONG((char *) addr - (char *) heap_start));
    } else
        fprintf(stderr, "FREE  at : %lu \n", ULONG(0));

}

void print_alloc_info(void *addr, int size)
{

    if (addr) {
        fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n",
            ULONG((char *) addr - (char *) heap_start), size);
    } else
        fprintf(stderr, "Warning, system is out of memory\n");

}

void print_alloc_error(int size)
{ fprintf(stderr, "ALLOC error : can't allocate %d bytes\n", size); }

#ifdef MAIN
int main(int argc, char **argv) {

    // The main can be changed, it is *not* involved in tests.
    memory_init();
    print_info();

    int i;
    for (i = 0; i < 10; i++) {
        char *b = memory_alloc(rand() % 8);
        memory_free(b);
    }

    char *a = memory_alloc(15);
    memory_free(a);

    a = memory_alloc(10);
    memory_free(a);

    fprintf(stderr, "%lu\n", (long unsigned int) (memory_alloc(9)));
    return EXIT_SUCCESS;

}
#endif
