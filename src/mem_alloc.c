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
#define FB_SIZE (sizeof(struct mem_free_block))
#define AB_SIZE (sizeof(struct mem_used_block))

// Pointer to the beginning of the memory region to manage.
void *heap_start;

// Pointer to the first free block in the heap.
mem_free_block_t *first_free;

/* -------------------------------------------------------------------------- */
#if defined(FIRST_FIT)

void *memory_alloc_policy(size_t size)
{

    size_t remaining_space;
    mem_free_block_t *previous, *current;

    previous = NULL;
    current = first_free;
    while (current != NULL) {
        if (current->size + AB_SIZE > size) {
            // remaining space = "real" block size - allocated block size
            remaining_space = (FB_SIZE + current->size) - (AB_SIZE + size);

            // If there is no place for a new free block, the function returns
            // the complete current block, with the remaining space.
            if (remaining_space < FB_SIZE) {
                if (previous == NULL)
                    first_free = current->next;
                else {
                    previous->next = current->next;
                    current->next = NULL;
                }
                return (void *) current;
            }

            mem_free_block_t *new_free_block;
            /*
                The newly allocated block has the following structure,
                [size; 0, 1, 2, ..., size -2, size - 1]
                so the address of the new free block is located at address
                sizeof(size) + size.
            */
            new_free_block =
                (mem_free_block_t *) ((char *) current + (AB_SIZE + size));
            new_free_block->size = remaining_space - FB_SIZE;
            new_free_block->next = current->next;

            if (previous == NULL)
                first_free = new_free_block;
            else {
                previous->next = new_free_block;
                current->next = NULL;
            }
            return (void *) current;
        }

        /*
            This following of code is equivalent to the lines 42-50. This is
            because if the function finds a free block with a size equal to the
            size we want to allocate, the remaining space after that allocation
            would be too small to create a new free block, hence the simalarity.
        */
        if (current->size == size) {
            if (previous == NULL)
                first_free = current->next;
            else {
                previous->next = current->next;
                current->next = NULL;
            }
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
    first_free->size = MEMORY_SIZE - FB_SIZE;
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
    print_alloc_info((char *) allocated_block + AB_SIZE, size);
    return (void *) ((char *) allocated_block + AB_SIZE);

}

// Given a freed block of memory and an already free block, which appears before
// in the free list. This function links this previous block with the newly
// freed one, and coalesces it if necessary.
static void coalescing_previous(mem_free_block_t *freed, mem_free_block_t *prev)
{

    char *end_prev, *begin_freed;

    if (prev != NULL)
        end_prev = (char *) prev + (FB_SIZE + prev->size);
    else
        end_prev = (char *) first_free + (FB_SIZE + first_free->size);
    begin_freed = (char *) freed;

    if (prev == NULL) {
        first_free = freed;
    } else if (end_prev < begin_freed) {
        prev->next = freed;
    } else if (end_prev == begin_freed) {
        prev->size += (FB_SIZE + freed->size);
        prev->next = freed->next;
        freed = NULL;
    }

}

void memory_free(void *p)
{

    size_t size;
    char *begin_address, *end_address;
    mem_free_block_t *freed_block, *current_free, *previous_free;

    begin_address = (char *) p - AB_SIZE;
    size = memory_get_allocated_block_size(p);
    end_address = begin_address + AB_SIZE + size;

    freed_block = (mem_free_block_t *) begin_address;
    freed_block->size = (AB_SIZE + size) - FB_SIZE;

    current_free = first_free;
    previous_free = NULL;
    while (current_free != NULL) {
        if (end_address < (char *) current_free) {
            freed_block->next = current_free;
            coalescing_previous(freed_block, previous_free);
            break;
        } else if (end_address == (char *) current_free) {
            freed_block->size += (FB_SIZE + current_free->size);
            freed_block->next = current_free->next;
            current_free = NULL;
            coalescing_previous(freed_block, previous_free);
            break;
        }

        previous_free = current_free;
        current_free = current_free->next;
    }
    print_free_info(p);

}

size_t memory_get_allocated_block_size(void *addr)
{

    size_t size;
    mem_used_block_t *real_address;

    real_address = (mem_used_block_t *) addr - 1;
    size = real_address->size;

    return size;

}


void print_mem_state(void)
{

    char *address;
    int i = 0;
    size_t segment = MEMORY_SIZE / 8;
    mem_free_block_t *previous, *current;

    previous = NULL;
    current = first_free;
    while (current != NULL) {
        if (previous == NULL && (char *) current != (char *) heap_start) {
            for (address = (char *) heap_start; address < (char *) current; address++) {
                fprintf(stderr, "X");
                i++;
                if (i == segment) {
                    fprintf(stderr, "\n");
                    i = 0;
                }
            }
        }
        for (address = (char *) current; address < (char *) current + FB_SIZE; address++) {
            fprintf(stderr, "X");
            i++;
            if (i == segment) {
                fprintf(stderr, "\n");
                i = 0;
            }
        }
        for (address = (char *) current + FB_SIZE; address < (char *) current + FB_SIZE + current->size; address++) {
            fprintf(stderr, ".");
            i++;
            if (i == segment) {
                fprintf(stderr, "\n");
                i = 0;
            }
        }
        current = current->next;
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
