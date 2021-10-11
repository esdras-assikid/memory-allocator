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
#define FBLOCK_SIZE (sizeof(struct mem_free_block))
#define ABLOCK_SIZE (sizeof(struct mem_used_block))

#if defined(FIRST_FIT)

/* TODO: code specific to the FIRST FIT allocation policy can be
 * inserted here */

void* mem_alloc_mod(size_t size){

    mem_free_block_t *best_block, *last_block;
    mem_used_block_t *assignblock;
    best_block = first_free;
    last_block = first_free;


    while(best_block != NULL){
        if(best_block->size + FBLOCK_SIZE - ABLOCK_SIZE>= size){
            if((void*) best_block + ABLOCK_SIZE % MEM_ALIGNMENT == 0){
                return (void*) best_block;
            }else{
                int mod = ((void*)best_block + ABLOCK_SIZE) % MEM_ALIGNMENT;
                if(mod+ABLOCK_SIZE+ size <= FBLOCK_SIZE+ best_block->size){
                    return (void *) best_block;
                }else{
                     last_block = best_block;
                     best_block = best_block->next;
                }
            }
            


        }else{
            last_block = best_block;
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
            if(block->size + FBLOCK_SIZE - ABLOCK_SIZE >= size){
                    if(block->size + FBLOCK_SIZE - ABLOCK_SIZE - size < minsize){
                        if((void*) block + ABLOCK_SIZE % MEM_ALIGNMENT == 0){
                            minsize = block->size + FBLOCK_SIZE - ABLOCK_SIZE - size;
                            best_fit = block;
                        } else{
                            int mod = ((void*)block + ABLOCK_SIZE) % MEM_ALIGNMENT;
                            if(mod+ABLOCK_SIZE+ size <= FBLOCK_SIZE+ block->size){
                                minsize = block->size + FBLOCK_SIZE - ABLOCK_SIZE - size;
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
                if(block->size >= size+ABLOCK_SIZE-FBLOCK_SIZE){
                    if((void*) block + ABLOCK_SIZE % MEM_ALIGNMENT == 0){
                        next_fit = block;
                        c = 0;
                    }else{
                        int mod = ((void*)block + ABLOCK_SIZE) % MEM_ALIGNMENT;
                        if(mod+ABLOCK_SIZE+ size <= FBLOCK_SIZE+ block->size){
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
                if(block->size >= size+ABLOCK_SIZE-FBLOCK_SIZE){
                    if((void*) block + ABLOCK_SIZE % MEM_ALIGNMENT == 0){
                        next_fit = block;
                        c = 0;
                    }else{
                        int mod = ((void*)block + ABLOCK_SIZE) % MEM_ALIGNMENT;
                        if(mod+ABLOCK_SIZE+ size <= FBLOCK_SIZE+ block->size){
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
    first_free = heap_start;
    first_free->size = MEMORY_SIZE - FBLOCK_SIZE;
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
    size_t mod = (void*)allocated_block + ABLOCK_SIZE % MEM_ALIGNMENT;

     assignblock = (mem_used_block_t *) ((void *)allocated_block +mod);


    size_t newsize = FBLOCK_SIZE + allocated_block->size - size - ABLOCK_SIZE - mod;
            if(newsize < FBLOCK_SIZE){
                assignblock->size = size + newsize;
                if(allocated_block == last_block){
                    first_free = allocated_block->next;
                }else{
                     while(last_block->next != allocated_block){
                        last_block = last_block->next;
                    }
                    last_block->next = allocated_block->next;
                }
                update_next_free(allocated_block->next);
            }else {
                assignblock->size = size;
                mem_free_block_t *new_block;
                new_block = (mem_free_block_t *) ((void *)assignblock + ABLOCK_SIZE+size);
                new_block->size= newsize;
                new_block->next = allocated_block->next;
                if(allocated_block == last_block){
                    first_free = new_block;
                }else{
                     while(last_block->next != allocated_block){
                        last_block = last_block->next;
                    }
                    last_block->next = new_block;
                }
                update_next_free(new_block);
            }
    print_alloc_info( (void *) ((char *) assignblock + ABLOCK_SIZE), size);
    return (void *) ((char *) assignblock + ABLOCK_SIZE);


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
        end_prev = (char *) prev + (FBLOCK_SIZE + prev->size);
    else
        end_prev = (char *) first_free + (FBLOCK_SIZE + first_free->size);
    begin_freed = (char *) freed;

    if (prev == NULL) {
        first_free = freed;
    } else if (end_prev < begin_freed) {
        prev->next = freed;
    } else if (end_prev == begin_freed) {
        prev->size += (FBLOCK_SIZE + freed->size);
        prev->next = freed->next;
        freed = NULL;
    }

}

void memory_free(void *p)
{

    size_t size;
    char *begin_address, *end_address;
    mem_free_block_t *freed_block, *current_free, *previous_free;

    begin_address = (char *) p - ABLOCK_SIZE;
    size = memory_get_allocated_block_size(p);
    end_address = begin_address + ABLOCK_SIZE + size;

    freed_block = (mem_free_block_t *) begin_address;
    freed_block->size = (ABLOCK_SIZE + size) - FBLOCK_SIZE;

    current_free = first_free;
    previous_free = NULL;
    while (current_free != NULL) {
        if (end_address < (char *) current_free) {
            freed_block->next = current_free;
            coalescing_previous(freed_block, previous_free);
            break;
        } else if (end_address == (char *) current_free) {
            freed_block->size += (FBLOCK_SIZE + current_free->size);
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

/*
void memory_free(void *p)
{

    mem_used_block_t *assignblock = p - ABLOCK_SIZE;
    mem_free_block_t *f_block = first_free;
    mem_free_block_t *l_block = first_free;

    while((void*) f_block < (void*)assignblock){
        l_block = f_block;
        f_block = f_block->next;
    }

    if(l_block == f_block){
        if((void*) l_block == (void*) assignblock+ABLOCK_SIZE+assignblock->size+1){
            size_t nsize = assignblock->size+FBLOCK_SIZE+f_block->size;
            f_block =(void *) assignblock;
            f_block->size = nsize;

            first_free = f_block;
        }else{
            mem_free_block_t* newFBlock = (void *)assignblock;
            newFBlock->next = f_block;
            first_free = newFBlock;

        }
    }else{
        if((void *) (l_block+FBLOCK_SIZE+l_block->size+1) == (void *)assignblock){
            if((void *)assignblock+ABLOCK_SIZE+assignblock->size+1 == (void *)f_block){
                l_block->size = l_block->size + ABLOCK_SIZE+assignblock->size+ FBLOCK_SIZE+ f_block->size;
                l_block->next = f_block->next;
            }else{
               l_block->size = l_block->size + ABLOCK_SIZE+assignblock->size;
               l_block->next = f_block;
            }
        }else{
            if((void *)assignblock+ABLOCK_SIZE+assignblock->size+1 == (void *) (f_block)){
                mem_free_block_t *newFBlock = (void *)assignblock;
                newFBlock->size = ABLOCK_SIZE+assignblock->size+f_block->size;
                newFBlock->next = f_block->next;
                l_block->next = newFBlock;
            }else{
                mem_free_block_t *newFBlock = (void *)assignblock;
                newFBlock->size = ABLOCK_SIZE+assignblock->size-FBLOCK_SIZE;
                newFBlock->next = f_block;
                l_block->next = newFBlock;
            }

        }
    }


    update_next_fit();
    print_free_info(p);

}
*/

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
                fprintf(stderr, "X"); i++;
                if (i == segment) {
                    fprintf(stderr, "\n");
                    i = 0;
                }
            }
        } else if (current == heap_start) {
            previous = current;
            for (address = (char *) current; address > (char *) previous + FBLOCK_SIZE + previous->size; address--) {
                fprintf(stderr, "X"); i++;
                if (i == segment) {
                    fprintf(stderr, "\n");
                    i = 0;
                }
            }
        } else {
            for (address = (char *) current; address > (char *) previous + FBLOCK_SIZE + previous->size; address--) {
                fprintf(stderr, "X"); i++;
                if (i == segment) {
                    fprintf(stderr, "\n");
                    i = 0;
                }
            }
        }
        for (address = (char *) current; address < (char *) current + FBLOCK_SIZE; address++) {
            fprintf(stderr, "H"); i++;
            if (i == segment) {
                fprintf(stderr, "\n");
                i = 0;
            }
        }
        for (address = (char *) current + FBLOCK_SIZE; address < (char *) current + FBLOCK_SIZE + current->size; address++) {
            fprintf(stderr, "."); i++;
            if (i == segment) {
                fprintf(stderr, "\n");
                i = 0;
            }
        }
        previous = current;
        current = current->next;
    }
    fprintf(stderr, "\n");


}



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
