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
    while (current != NULL) { // Traversing the free list
        if (current->size > size) { // If a larger than necessary block is found
            if (current->size - size - FBLOCK_SIZE < FBLOCK_SIZE)
                return NULL;
            mem_free_block_t *new_free_block; // We create a new free block
            // This block is located at
            new_free_block = (mem_free_block_t *) ((char *) current + (ABLOCK_SIZE + size));
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
    if (allocated_block == NULL) {
        print_alloc_error(size);
        exit(0);
    }
    allocated_block->size = size;
    print_alloc_info((char *) allocated_block + ABLOCK_SIZE, size);
    return (void *) ((char *) allocated_block + ABLOCK_SIZE);

}

void memory_free(void *p)
{

    /* TODO: insert your code here */
    size_t size;
    char *begin_address, *end_address, *end_previous_free;
    mem_free_block_t *freed_block, *current_free, *previous_free;

    begin_address = (char *) p - ABLOCK_SIZE;
    size = *(size_t *) begin_address;
    end_address = begin_address + ABLOCK_SIZE + size;

    freed_block = (mem_free_block_t *) begin_address;
    freed_block->size = (ABLOCK_SIZE + size) - FBLOCK_SIZE;

    current_free = first_free;
    previous_free = current_free;
    while (current_free != NULL) {
        // end_current_free = (char *) current_free + (FBLOCK_SIZE + current_free->size);
        end_previous_free = (char *) previous_free + (FBLOCK_SIZE + previous_free->size);
        if (end_address < (char *) current_free) {
            freed_block->next = current_free;
            if (previous_free != current_free)
                previous_free->next = freed_block;
            if (end_previous_free == begin_address)
                previous_free->size += (FBLOCK_SIZE + freed_block->size);
            if (current_free == first_free)
                first_free = freed_block;
            break;
        } else if (end_address == (char *) current_free) {
            freed_block->next = current_free;
            freed_block->size += (FBLOCK_SIZE + current_free->size);
            if (previous_free != current_free)
                previous_free->next = freed_block;
            if (end_previous_free == begin_address)
                previous_free->size += (FBLOCK_SIZE + freed_block->size);
            if (current_free == first_free)
                first_free = freed_block;
            break;
        }
        previous_free = current_free;
        current_free = current_free->next;
    }
    print_free_info(p);

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
        fprintf(stderr, "FREE BLOCK at %ld (%ld bytes) ->\n",
            ULONG((char *) i - (char *) heap_start), i->size);
        i = i->next;
    }
    return;

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
