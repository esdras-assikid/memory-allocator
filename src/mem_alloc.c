#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>


#include "mem_alloc_types.h"
#include "my_mmap.h"

/* pointer to the beginning of the memory region to manage */
void *heap_start;

/* Pointer to the first free block in the heap */
mem_free_block_t *first_free;
mem_free_block_t *next_free;


#define ULONG(x)((long unsigned int)(x))
#define FB_SIZE (sizeof(struct mem_free_block))
#define AB_SIZE (sizeof(struct mem_used_block))
#define MG_NUMB 123456789

#if defined(FIRST_FIT)

/* TODO: code specific to the FIRST FIT allocation policy can be
 * inserted here */

void* mem_alloc_mod(size_t size){

    mem_free_block_t *best_block;
    best_block = first_free;

    while(best_block != NULL){
        if(best_block->size + FB_SIZE - AB_SIZE >= size){
            if(ULONG((char *) best_block + AB_SIZE) % MEM_ALIGNMENT == 0){
                return (char *) best_block;
            }else{
                int mod = ULONG((char *)best_block + AB_SIZE) % MEM_ALIGNMENT;
                if(MEM_ALIGNMENT - mod+AB_SIZE+ size <= FB_SIZE+ best_block->size){
                    return (char  *) best_block;
                }else{
                    best_block = best_block->next;
                }
            }



        }else{
            best_block = best_block->next;
        }
    }
    return NULL;



}
void update_next_free(mem_free_block_t *new_block){
}
void update_next_fit(){

}

/* You can define here functions that will be compiled only if the
 * symbol FIRST_FIT is defined, that is, only if the selected policy
 * is FF */


#elif defined(BEST_FIT)
    void* mem_alloc_mod(size_t size){
        mem_free_block_t *block = first_free;
        mem_free_block_t *best_fit = NULL;
        size_t minsize = INT_MAX;
        while(block !=NULL){
            if(block->size + FB_SIZE - AB_SIZE>= size){
                    if(block->size + FB_SIZE - AB_SIZE - size < minsize){
                        if (ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT == 0){
                            minsize = block->size + FB_SIZE - AB_SIZE - size;
                            best_fit = block;
                        } else{
                            unsigned long int mod = ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT;
                            if(MEM_ALIGNMENT - mod + AB_SIZE+ size <= FB_SIZE+ block->size){
                                minsize = block->size + FB_SIZE - AB_SIZE - size;
                                best_fit = block;
                            }
                        }
                    }
            }
            block = block->next;
        }
        return best_fit;
    }
    void update_next_free(mem_free_block_t *new_block){
    }
    void update_next_fit(){

    }


/* TODO: code specific to the BEST FIT allocation policy can be
 * inserted here */

#elif defined(NEXT_FIT)
void* mem_alloc_mod(size_t size){
        mem_free_block_t *block = next_free;
        mem_free_block_t *next_fit = NULL;
        int c = 1;
        while(c){
            if(block == NULL){
                c = 0;
            }else{
                if(block->size >= size+AB_SIZE-FB_SIZE){
                    if (ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT == 0){
                        next_fit = block;
                        c = 0;
                    }else{
                        unsigned long int mod = ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT;
                        if(MEM_ALIGNMENT - mod + AB_SIZE + size <= FB_SIZE + block->size){
                            next_fit = block;
                            c = 0;
                        }
                    }
                }
                block = block->next;
            }
        }
        if(next_fit == NULL){
            block = first_free;
            c= 1;
            while(c){
            if(block == NULL){
                c = 0;
            } else {
                if(block->size >= size+AB_SIZE-FB_SIZE){
                    if(ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT == 0){
                        next_fit = block;
                        c = 0;
                    }else{
                        unsigned long int mod = ULONG((char *) block + AB_SIZE) % MEM_ALIGNMENT;
                        if(MEM_ALIGNMENT - mod + AB_SIZE+ size <= FB_SIZE+ block->size){
                            next_fit = block;
                            c = 0;
                        }
                    }
                }
                block = block->next;
            }
        }
        }

        return next_fit;
}

void update_next_free(mem_free_block_t *new_block){
    next_free = new_block;
}
void update_next_fit(){
    mem_free_block_t *block = first_free;
    mem_free_block_t *last_block = first_free;
    mem_free_block_t *next_fit = next_free;

    while(block !=NULL){
        if(block == next_fit){
            break;
        }
        else if(next_fit < block){
            next_free = last_block;
            break;
        }
        last_block = block;
        block = block->next;
    }
    next_free = next_fit;
}



/* TODO: code specific to the NEXT FIT allocation policy can be
 * inserted here */

#endif


void run_at_exit(void)
{
    fprintf(stderr,"YEAH B-)\n");

    /* TODO: insert your code here */
}




void memory_init(void)
{
    /* register the function that will be called when the programs exits */
    atexit(run_at_exit);

    heap_start = my_mmap(MEMORY_SIZE);
    first_free = (mem_free_block_t *) heap_start;
    first_free->size = MEMORY_SIZE - FB_SIZE;
    first_free->next = NULL;
    next_free = first_free;

    /* TODO: insert your code here */

    /* TODO: start by using the provided my_mmap function to allocate
     * the memory region you are going to manage */

}

void *memory_alloc(size_t size)
{

    /* TODO: insert your code here */
    mem_free_block_t *allocated_block;
    mem_used_block_t *assignblock;
    mem_free_block_t *last_block;

    last_block = first_free;

    allocated_block = (mem_free_block_t *) mem_alloc_mod(size);
    if (allocated_block == NULL) {
        print_alloc_error(size);
        exit(0);
    }
    size_t mod = ULONG((char *) allocated_block + AB_SIZE) % MEM_ALIGNMENT;

    size_t newsize = 0;
    if (mod == 0) {
        assignblock = (mem_used_block_t *) ((char *) allocated_block);
        newsize = FB_SIZE + allocated_block->size - size - AB_SIZE;
    } else {
        assignblock = (mem_used_block_t *) ((char *) allocated_block + MEM_ALIGNMENT - mod);
        newsize = FB_SIZE + allocated_block->size - size - AB_SIZE - MEM_ALIGNMENT+ mod;
    }

    if (newsize < FB_SIZE) {
        assignblock->size = size + newsize;
        if (allocated_block == last_block) {
            first_free = allocated_block->next;
        } else {
            while (last_block->next != allocated_block) {
                last_block = last_block->next;
            }
            last_block->next = allocated_block->next;
        }
        update_next_free(allocated_block->next);
        assignblock->magic_number = MG_NUMB;
    } else {
        assignblock->size = size;
        mem_free_block_t *new_block;
        new_block = (mem_free_block_t *) ((void *) assignblock + AB_SIZE + size);
        new_block->size= newsize;
        new_block->next = allocated_block->next;
        if (allocated_block == last_block) {
            first_free = new_block;
        } else {
            while (last_block->next != allocated_block) {
                last_block = last_block->next;
            }
            last_block->next = new_block;
        }
        update_next_free(new_block);
        assignblock->magic_number = MG_NUMB;
    }
    print_alloc_info((void *) ((char *) assignblock + AB_SIZE), size);
    return (void *) ((char *) assignblock + AB_SIZE);


    /* TODO : don't forget to call the function print_alloc_info()
     * appropriately */
}

// Given a freed block of memory and an already free block, which appears before
// in the free list. This function links this previous block with the newly
// freed one, and coalesces it if necessary.
static void coalescing_previous(mem_free_block_t *freed, mem_free_block_t *prev)
{

    char *end_prev, *begin_freed;

    if (prev != NULL)
        end_prev = (char *) prev + (FB_SIZE + prev->size);/* TODO: DEFINE */
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
    update_next_fit();

}
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
        fprintf(stderr, "%d allocated block(s) still in use and %d free "
            "block(s).\n", ab_nb, fb_nb);
    }
    fprintf(stderr, "\n");

}

void print_mem_state(void) { mem_state(1); }
/* -------------------- MEMORY STATE VISUALIZATION - END -------------------- */


void print_info(void) {
    fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", (long unsigned int) heap_start, (long unsigned int) ((char*)heap_start+MEMORY_SIZE), (long unsigned int) (MEMORY_SIZE));
}

void print_free_info(void *addr){
    if(addr){
        fprintf(stderr, "FREE  at : %lu \n", ULONG((char*)addr - (char*)heap_start));
    }
    else{
        fprintf(stderr, "FREE  at : %lu \n", ULONG(0));
    }

}

void print_alloc_info(void *addr, int size){
  if(addr){
    fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n",
	    ULONG((char*)addr - (char*)heap_start), size);
  }
  else{
    fprintf(stderr, "Warning, system is out of memory\n");
  }
}

void print_alloc_error(int size)
{
    fprintf(stderr, "ALLOC error : can't allocate %d bytes\n", size);
}


#ifdef MAIN
int main(int argc, char **argv){

  /* The main can be changed, it is *not* involved in tests */
  memory_init();
  print_info();
  int i ;
  for( i = 0; i < 10; i++){
    char *b = memory_alloc(rand()%8);
    memory_free(b);
  }

  char * a = memory_alloc(15);
  memory_free(a);


  a = memory_alloc(10);
  memory_free(a);

  fprintf(stderr,"%lu\n",(long unsigned int) (memory_alloc(9)));
  return EXIT_SUCCESS;
}
#endif
