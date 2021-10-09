#ifndef _MEM_ALLOC_TYPES_H_
#define _MEM_ALLOC_TYPES_H_

// Structure declaration for a free block.
struct mem_free_block {
    size_t size;
    struct mem_free_block *next;
};
typedef struct mem_free_block mem_free_block_t;

// Specific metadata for used blocks.
struct mem_used_block {
    size_t size;
    int magic_number;
};
typedef struct mem_used_block mem_used_block_t;

#endif
