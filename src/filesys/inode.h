#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

#define DIR 2
#define FILE 1

struct bitmap;

void cache_init (void);
void write_back_cache_list(bool halt);
void inode_init (void);
bool inode_create (block_sector_t, off_t, bool is_dir);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
int inode_get_open_cnt(const struct inode *);
int getProperty(struct inode *);
block_sector_t getInumber(const struct inode *inode);
//struct inode *dir_getInode(struct dir *);
//struct inode *file_getInode(struct file *);
block_sector_t inode_getSector(struct inode *);
block_sector_t inode_get_parent (const struct inode *);
bool inode_add_parent(block_sector_t, block_sector_t);
void inode_lock_acquire(struct inode *);
void inode_lock_release(struct inode *);
#endif /* filesys/inode.h */
