#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

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
#define MG_NUMB 123456789

// Pointer to the beginning of the memory region to manage.
void *heap_start;

// Pointer to the first free block in the heap.
mem_free_block_t *first_free;

// Pointer to the next free block in the heap.
mem_free_block_t *next_free;

/* ------------------- MEMORY ALLOCATION POLICIES - START ------------------- */
#if defined(FIRST_FIT)

void *memory_alloc_policy(size_t size, mem_free_block_t **previous_block)
{

    mem_free_block_t *current_block;

    current_block = first_free;
    while (current_block != NULL) {
        if (FB_SIZE + current_block->size >= AB_SIZE + size)
            return (void *) current_block;

        *previous_block = current_block;
        current_block = current_block->next;
    }

    return NULL;

}

#elif defined(BEST_FIT)

void *memory_alloc_policy(size_t size, mem_free_block_t **previous_block)
{

    mem_free_block_t *previous, *current_block, *best_block;
    size_t min_size = ULONG_MAX, remaining_space;

    previous = NULL;
    best_block = NULL;
    current_block = first_free;
    while (current_block != NULL) {
        if (FB_SIZE + current_block->size >= AB_SIZE + size) {
            remaining_space =
                (FB_SIZE + current_block->size) - (AB_SIZE + size);
            if (remaining_space < min_size) {
                *previous_block = previous; // Keeping the previous block before
                best_block = current_block; // best_block.
                min_size = remaining_space;
            }
        }

        previous = current_block;
        current_block = current_block->next;
    }

    return (void *) best_block;

}

#elif defined(NEXT_FIT)

void *memory_alloc_policy(size_t size, mem_free_block_t **previous_block)
{

    mem_free_block_t *current_block;

    current_block = next_free;
    do {
        if (FB_SIZE + current_block->size >= AB_SIZE + size)
            return (void *) current_block;

        if (current_block->next == NULL) {
            *previous_block = NULL;
            current_block = first_free;
        } else {
            *previous_block = current_block;
            current_block = current_block->next;
        }
    } while (current_block != next_free);

    return NULL;

}

#endif
void update_next_free(mem_free_block_t *new_next_free)
{

    if (new_next_free != NULL)
        next_free = new_next_free;
    else
        next_free = first_free;
    return;

}
/* -------------------- MEMORY ALLOCATION POLICIES - END -------------------- */

/* ------------------------- INITIALIZATION - START ------------------------- */
void run_at_exit(void) { mem_state(0); }

void memory_init(void)
{

    atexit(run_at_exit);

    heap_start = my_mmap(MEMORY_SIZE);
    first_free = (mem_free_block_t *) heap_start;
    first_free->size = MEMORY_SIZE - FB_SIZE;
    first_free->next = NULL;
    next_free = first_free;

    return;

}
/* -------------------------- INITIALIZATION - END -------------------------- */

/* ----------------------- MEMORY ALLOCATION - START ------------------------ */
void *memory_alloc(size_t size)
{

    mem_free_block_t *used_free_block, *previous_block;
    mem_used_block_t *allocated_block;
    size_t remaining_space;

    previous_block = NULL;
    used_free_block =
        (mem_free_block_t *) memory_alloc_policy(size, &previous_block);
    if (used_free_block == NULL) {
        print_alloc_error(size);
        exit(0);
    }
    allocated_block = (mem_used_block_t *) used_free_block;

    // remaining space = "real" block size - allocated block size
    remaining_space = (FB_SIZE + used_free_block->size) - (AB_SIZE + size);
    // If there is no place for a new free block, the function allocates
    // the complete current block, with the remaining space.
    if (remaining_space < FB_SIZE) {
        if (previous_block == NULL)
            first_free = used_free_block->next;
        else {
            previous_block->next = used_free_block->next;
            used_free_block->next = NULL;
        }
        update_next_free(used_free_block->next);
        allocated_block->size = size + remaining_space;
        allocated_block->magic_number = MG_NUMB;
    } else {
        mem_free_block_t *new_free_block;
        /*
            The newly allocated block has the following structure,
            [size; 0, 1, 2, ..., size -2, size - 1]
            so the address of the new free block is located at address
            sizeof(size) + size.
        */

        new_free_block =
            (mem_free_block_t *) ((char *) used_free_block + (AB_SIZE + size));
        new_free_block->size = remaining_space - FB_SIZE;
        new_free_block->next = used_free_block->next;

        if (previous_block == NULL)
            first_free = new_free_block;
        else {
            previous_block->next = new_free_block;
            used_free_block->next = NULL;
        }
        update_next_free(new_free_block);
        allocated_block->size = size;
        allocated_block->magic_number = MG_NUMB;
    }

    print_alloc_info((char *) allocated_block + AB_SIZE, size);
    return (void *) ((char *) allocated_block + AB_SIZE);

}
/* ------------------------- MEMORY ALLOCATION - END ------------------------ */

/* ------------------------- MEMORY FREEING - START ------------------------- */
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
        if (freed == next_free)
            update_next_free(prev);
        freed = NULL;
    }

}

void memory_free(void *p)
{

    if (p != NULL && is_alloc(p)) {
        size_t size;
        char *begin_address, *end_address;
        mem_free_block_t *freed_block, *current_free, *previous_free;

        size = memory_get_allocated_block_size(p);
        begin_address = (char *) p - AB_SIZE;
        end_address = begin_address + AB_SIZE + size;

        freed_block = (mem_free_block_t *) begin_address;
        freed_block->size = (AB_SIZE + size) - FB_SIZE;
        freed_block->next = NULL;

        previous_free = NULL;
        current_free = first_free;
        while (current_free != NULL) {
            if (end_address < (char *) current_free) {
                freed_block->next = current_free;
                coalescing_previous(freed_block, previous_free);
                break;
            } else if (end_address == (char *) current_free) {
                freed_block->size += (FB_SIZE + current_free->size);
                freed_block->next = current_free->next;
                current_free = NULL;
                if (end_address == (char *) next_free)
                    update_next_free(freed_block);
                coalescing_previous(freed_block, previous_free);
                break;
            }

            previous_free = current_free;
            current_free = current_free->next;
        }

        // first_free == NULL means the heap is full.
        if (first_free == NULL) {
            first_free = freed_block;
            update_next_free(first_free);
        }

        print_free_info(p);
        return;
    }
    print_free_error(p);

}
/* -------------------------- MEMORY FREEING - END -------------------------- */

/* ----------------------------- UTILS - START ------------------------------ */
size_t memory_get_allocated_block_size(void *addr)
{

    size_t size;
    mem_used_block_t *real_address;

    real_address = (mem_used_block_t *) addr - 1;
    size = real_address->size;

    return size;

}

int is_alloc(void *addr)
{

    if (addr != NULL) {
        mem_used_block_t *real_address;

        real_address = (mem_used_block_t *) addr - 1;
        if (real_address->magic_number != MG_NUMB)
            return 0;
        return 1;
    }
    return 0;

}
/* ------------------------------ UTILS - END ------------------------------- */

/* ------------------- MEMORY STATE VISUALIZATION - START ------------------- */
// Used by the different printing functions in order to print 128 characters per
// line. i is incremented each time a character is printed and reverted back to
// zero once a line is completed.
static int line_len = 128, i = 0;

static void print_mem_block(void *start, void *end, char c)
{

    char *address;
    for (address = (char *) start; address < (char *) end; address++) {
        fprintf(stderr, "%c", c); i++;
        if (i == line_len) {
            fprintf(stderr, "\n");
            i = 0;
        }
    }

}

static void print_alloc_block(void *start, void *end, int *ab_nb, int is_print)
{

    char *address;

    address = (char *) start + AB_SIZE;
    while (address - AB_SIZE != (char *) end) {
        if (is_print) {
            print_mem_block(address - AB_SIZE, address, 'A');
            print_mem_block(address,
                address + memory_get_allocated_block_size(address), 'X'
            );
        }
        address += (AB_SIZE + memory_get_allocated_block_size(address));
        *ab_nb += 1;
    }

}

/*
    is_print is a boolean used to specify if the functions involved in the
    checking of the memory state should print either a visual representation of
    the memory or simply the number of allcoated and free blocks.
    is_print == 0 -> simple displaying
    is_print == 1 -> visual representation
*/
void mem_state(int is_print)
{

    char *address, *hp = (char *) heap_start;
    mem_free_block_t *previous_block, *current_block;
    int fb_nb = 0, ab_nb = 0; // free and allocated block number

    previous_block = NULL;
    current_block = first_free;
    while (current_block != NULL) { // Traversing the free list
        // If the first free block is not heap_start and the block is allocated.
        if (previous_block == NULL &&
            (char *) current_block != hp &&
            is_alloc(hp + AB_SIZE)
        )
            print_alloc_block(heap_start, current_block, &ab_nb, is_print);
        else if (previous_block != NULL) {
            // Prints allocated block beetween the previous free block and
            // the currently traversed one.
            address = (char *) previous_block + FB_SIZE + previous_block->size;
            if (is_alloc(address + AB_SIZE))
                print_alloc_block(address, current_block, &ab_nb, is_print);
        }
        // Prints the currently traversed free block.
        address = (char *) current_block + FB_SIZE;
        if (is_print) {
            print_mem_block(current_block, address, 'F');
            print_mem_block(address, address + current_block->size, '.');
        } else
            fb_nb++;

        previous_block = current_block;
        current_block = current_block->next;
    }

    if (first_free == NULL && is_alloc(hp + AB_SIZE)) // If the heap is full.
        print_alloc_block(heap_start, hp + MEMORY_SIZE, &ab_nb, is_print);
    else if (address + previous_block->size != hp + MEMORY_SIZE &&
        is_alloc(address + previous_block->size + AB_SIZE)
    ) // If the free list ends before the end of the heap.
        print_alloc_block(address + previous_block->size, hp + MEMORY_SIZE,
            &ab_nb, is_print);

    if (!is_print) {
        if (ab_nb != 0)
            fprintf(stderr, "WARNING: un-freed memory could lead to a memory "
                "leak.\n");
        fprintf(stderr, "%d un-freed allocated block(s) and %d free block(s).\n"
            ,ab_nb, fb_nb);
    }
    fprintf(stderr, "\n");

}

void print_mem_state(void) { mem_state(1); }
/* -------------------- MEMORY STATE VISUALIZATION - END -------------------- */

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

void print_free_error(void *addr)
{

    if (addr == NULL)
        fprintf(stderr, "WARNING: freeing %p is illegal.\n", addr);
    else
        fprintf(stderr, "WARNING: %lu is already free\n",
            ULONG((char *) addr - (char *) heap_start));

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
