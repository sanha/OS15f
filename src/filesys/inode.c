#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define MAX_CACHE_SIZE 64

/* The number of blokcs */
#define DIRECT_BLOCKS 8
#define IND_BLOCKS 7
#define DOUBLE_IND_BLOKCS 1

/* The number of pointers direct or indirect inode has */
#define DIRECT_PTRS 16
#define INDIRECT_PTRS 128

#define DIRECT_BYTES DIRECT_BLOCKS*BLOCK_SECTOR_SIZE
#define SINGLE_IND_BYTES INDIRECT_PTRS*BLOCK_SECTOR_SIZE
#define INDIRECT_BYTES IND_BLOCKS*INDIRECT_PTRS*BLOCK_SECTOR_SIZE

static struct list cache_list;
static struct lock cache_lock;
static int cache_size;

struct cache_block* get_cache_block(block_sector_t sector, bool dirty);
struct cache_block* search_cache_block(block_sector_t sector, bool dirty);
struct cache_block* evict_cache_block(block_sector_t sector, bool dirty);
void write_back_cache(struct cache_block *cb);
bool cache_less_recent(const struct list_elem *left_elem, const struct list_elem *right_elem, void *aux UNUSED);


struct cache_block
{
	uint8_t *block;
	bool read;
	bool dirty;
	int64_t used_tick;
	block_sector_t sector;
	struct list_elem elem;
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
	uint32_t dir_idx;				/* direct index */
	uint32_t ind_idx;					/* first indirect index */
	uint32_t double_ind_idx;			/* second indirect index */
	block_sector_t ptr[DIRECT_PTRS];	/* Pointer to direct and indirect blocks */
    uint32_t unused[122 - DIRECT_PTRS]; /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
	return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
//    struct inode_disk data;             /* Inode content. */	//TODO: DELETE

	off_t length;						/* length of inode data */
	uint32_t dir_idx;               	/* direct index */
    uint32_t ind_idx;                   /* first indirect index */
    uint32_t double_ind_idx;            /* second indirect index */
    block_sector_t ptr[DIRECT_PTRS];    /* Pointer to direct and indirect blocks */ 
  };

void cache_init(void)
{
	list_init(&cache_list);
	lock_init(&cache_lock);
	cache_size = 0;
}

struct cache_block* get_cache_block(block_sector_t sector, bool dirty)
{
	struct cache_block *cb;	

	cb = search_cache_block(sector, dirty);
	
	if(cb == NULL)	cb = evict_cache_block(sector, dirty);

	return cb;
}

struct cache_block* search_cache_block(block_sector_t sector, bool dirty)
{
	struct cache_block *cb;
	struct list_elem *e;

	for(e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
	{
		cb = list_entry(e, struct cache_block, elem);
		if(cb->sector == sector)
		{
			cb->dirty |= dirty;
			cb->used_tick = timer_ticks;
			return cb;
		}
	}
	return NULL;
}

struct cache_block* evict_cache_block(block_sector_t sector, bool dirty)
{
	struct cache_block *cb;
	if(cache_size < MAX_CACHE_SIZE)
	{
		cb = malloc(sizeof(struct cache_block));
		cb->block = malloc(BLOCK_SECTOR_SIZE);
		memset(cb->block, 0, BLOCK_SECTOR_SIZE);
		list_push_back(&cache_list, &cb->elem);
	}
	else
	{
		list_sort(&cache_list, cache_less_recent, NULL);
		cb = list_entry(list_front(&cache_list), struct cache_block, elem);
		write_back_cache(cb);
	}
	
	cb->sector = sector;
	cb->used_tick = timer_ticks();
	cb->dirty = dirty;
	block_read(fs_device, sector, cb->block);
	return cb;
}

void write_back_cache(struct cache_block * cb)
{
	if(cb->dirty)
	{
		block_write(fs_device, cb->sector, cb->block);
		cb->dirty = false;
	}
}

void write_back_cache_list(bool halt)
{
	struct cache_block *cb;
	struct list_elem *next,*e;
	
	for(e = list_begin(&cache_list); e != list_end(&cache_list);)
	{
		next = list_next(e);
		cb = list_entry(e, struct cache_block, elem);
		write_back_cache(cb);
		if(halt)
		{
			list_remove(&cb->elem);
			free(cb->block);
			free(cb);
		}
		e = next;
	}
	
}


bool cache_less_recent(const struct list_elem *left_elem
			, const struct list_elem *right_elem
			, void *aux UNUSED)
{
	struct cache_block *left = list_entry(left_elem, struct cache_block, elem);
	struct cache_block *right = list_entry(right_elem, struct cache_block, elem);

	return left->used_tick < right->used_tick;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  	ASSERT (inode != NULL);
	if (pos < inode->length) {
		if (pos < BLOCK_SECTOR_SIZE * DIRECT_BLOCKS) {
			//printf ("	@ byte_to_sector: pos is %d, accessing index is %d, result sector is %d\n", pos, pos / BLOCK_SECTOR_SIZE, inode->ptr[pos / BLOCK_SECTOR_SIZE]);
			return inode->ptr[pos / BLOCK_SECTOR_SIZE];
		}
		pos -= DIRECT_BYTES;
		block_sector_t ptrs[INDIRECT_PTRS];
		if (pos < INDIRECT_BYTES) {	// first indirect level
			uint32_t idx = (pos / BLOCK_SECTOR_SIZE) / INDIRECT_PTRS + DIRECT_BLOCKS;	
			block_read(fs_device, inode->ptr[idx], ptrs);	// TODO: CHECK ptrs
			// now ptrs has block pointers	// TODO: CHECK IDX
			//printf("	@ byte_to_sector: ptrs' idx is %d, ptrs readed sector is %d, result sector is %d\n", (pos / BLOCK_SECTOR_SIZE) % INDIRECT_PTRS, inode->ptr[idx], ptrs[(pos / BLOCK_SECTOR_SIZE) % INDIRECT_PTRS]);
//			return ptrs[(pos % SINGLE_IND_BYTES) / BLOCK_SECTOR_SIZE];
			return ptrs[(pos / BLOCK_SECTOR_SIZE) % INDIRECT_PTRS];
		}
		pos -= INDIRECT_BYTES;
		block_sector_t ptrs2[INDIRECT_PTRS];
		// second	
		uint32_t idx = ((pos / BLOCK_SECTOR_SIZE) / INDIRECT_PTRS) / IND_BLOCKS; 
		block_read(fs_device, inode->ptr[DIRECT_PTRS-1], ptrs);
		// now ptrs has first-level indirect pointers
		printf("	@ byte_to_sector: idx is %d, ptrs2 readed sector is %d, result sector is %d\n", idx, ptrs[idx], ptrs2[(pos % SINGLE_IND_BYTES) / BLOCK_SECTOR_SIZE]);
		block_read(fs_device, ptrs[idx], ptrs2);
		// now ptrs2 has block pointers
		return ptrs2[(pos % SINGLE_IND_BYTES) / BLOCK_SECTOR_SIZE];
	}
//  return inode->data.start + pos / BLOCK_SECTOR_SIZE;
	else
    	return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* expand inode and allocate needed free-map. return successed length */
off_t inode_expand (struct inode *inode, off_t length);
/* free allocated area of inode */
void inode_free (struct inode *inode);

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  struct inode *tmp_inode = NULL;	// temporary in-memory inode
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  tmp_inode = calloc (1, sizeof *tmp_inode);
	if (disk_inode != NULL)
    {
	    disk_inode->length = length;
    	disk_inode->magic = INODE_MAGIC;

		tmp_inode->length = 0;
		tmp_inode->dir_idx = 0;
		tmp_inode->ind_idx = 0;
		tmp_inode->double_ind_idx= 0;
		tmp_inode->sector = sector;
		//printf ("	@ inode_create: required rength is %d, required sector is %d, expension called\n",length, sector);
		off_t successed = inode_expand (tmp_inode, length);	// get ptr to tmp_inode
		if (bytes_to_sectors(successed) == bytes_to_sectors(length)) {
			disk_inode->length = length;
			memcpy(disk_inode->ptr, tmp_inode->ptr, DIRECT_PTRS * sizeof(block_sector_t));	// TODO: CHECK
			disk_inode->dir_idx = tmp_inode->dir_idx;
			disk_inode->ind_idx = tmp_inode->ind_idx;
			disk_inode->double_ind_idx = tmp_inode->double_ind_idx;

			block_write (fs_device, sector, disk_inode);
			success = true;
		}
	  free (disk_inode);
	  free (tmp_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
  	//printf("	@ inode_open: malloc is faild.\n");
	  return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  struct inode_disk *disk_inode;
  disk_inode = calloc (1, sizeof *disk_inode);
  block_read (fs_device, inode->sector, disk_inode);
  inode->dir_idx = disk_inode->dir_idx;
  inode->ind_idx = disk_inode->ind_idx;
  inode->double_ind_idx = disk_inode->double_ind_idx;
  inode->length = disk_inode->length;
  memcpy(inode->ptr, disk_inode->ptr, DIRECT_PTRS * sizeof(block_sector_t));	// TODO: CHECK
  free (disk_inode);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) {
		inode_free(inode);
      }
	  else {
		struct inode_disk *disk_inode = calloc (1, sizeof *disk_inode);
        disk_inode->length = inode->length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->dir_idx = inode->dir_idx;
        disk_inode->ind_idx = inode->ind_idx;
        disk_inode->double_ind_idx = inode->double_ind_idx;
  		memcpy(disk_inode->ptr, inode->ptr, DIRECT_PTRS * sizeof(block_sector_t));	// TODO: CHECK
	    block_write(fs_device, inode->sector, disk_inode);
		free (disk_inode);
	  }
	  free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
	//printf ("	@ inode_remove: remove is called, inode's sector is %d\n", inode->sector);
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  //uint8_t *bounce = NULL;
  struct cache_block *cb;
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

	  lock_acquire(&cache_lock);
  	  //printf("	@ inode_read_at: block_read sector is %d\n",sector_idx);
 	  cb = get_cache_block(sector_idx,false);
	  memcpy(buffer + bytes_read, cb->block + sector_ofs, chunk_size);
      lock_release(&cache_lock);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  //uint8_t *bounce = NULL;
  struct cache_block *cb;
  if (inode->deny_write_cnt)
    return 0;

  if (size + offset > inode->length) {
	//printf ("	@ inode_write_at: call inode_expand. length is %d, sector is %d\n", inode->length, inode->sector);
	inode_expand (inode, size + offset);
  	inode->length = size + offset;
  }

  //printf("	@ inode_write_at: inode_write is called. inode's sector is %d, size is %d, offset is  %d\n",inode->sector,size, offset);
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
		
	  lock_acquire(&cache_lock);
  	  //printf("	@ inode_write_at: block_read sector is %d\n",sector_idx);
	  cb = get_cache_block(sector_idx, true);

	  if(!(sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
	  		&& !(sector_ofs > 0 || chunk_size < sector_left))
	  		memset(cb->block, 0, BLOCK_SECTOR_SIZE);
	  memcpy(cb->block + sector_ofs, buffer + bytes_written, chunk_size);
	  lock_release(&cache_lock);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->length;
}

void
print_inode_cnt(const struct inode *inode)
{
	//printf("deny_write_cnt : %d\n", inode->deny_write_cnt);
}


/* expand inode to given length and allocate needed free-map. return successed length */
off_t inode_expand (struct inode *inode, off_t length) {
	//printf ("	@ inode_expand: expand is called. required length is %d\n", length);
	//printf (" 	@ inode_expand: inode's length is %d, inode's sector is %d\n", inode->length, inode->sector);
	if (bytes_to_sectors(length) <= bytes_to_sectors(inode->length)) return inode->length;
	size_t left_sectors = bytes_to_sectors(length) - bytes_to_sectors(inode->length);
	off_t allocate_length = inode->length;
	int init[BLOCK_SECTOR_SIZE/4] = {0};
	//printf (" 	@ inode_expand: left sectors is %d\n", left_sectors);

	while (inode->dir_idx < DIRECT_BLOCKS) {
		free_map_allocate (1, &inode->ptr[inode->dir_idx]);
		//printf (" 	@ inode_expand: direct index is %d, target sector is %d\n", inode->dir_idx, inode->ptr[inode->dir_idx]);
		block_write(fs_device, inode->ptr[inode->dir_idx], init);
		inode->dir_idx ++;
		allocate_length += BLOCK_SECTOR_SIZE;
		left_sectors --;
		if (left_sectors == 0) {
			return length;
		}
	}
	block_sector_t ptrs[INDIRECT_PTRS];
	while (inode->dir_idx < DIRECT_BLOCKS + IND_BLOCKS) {
		if (inode->ind_idx == 0)
			free_map_allocate(1, &inode->ptr[inode->dir_idx]);
  		//printf("	@ inode_expand: dir_idx is %d, first indirect pointer sector is %d\n",inode->dir_idx, inode->ptr[inode->dir_idx]);
		block_read(fs_device, inode->ptr[inode->dir_idx], ptrs);
		while (inode->ind_idx < INDIRECT_PTRS) {
			free_map_allocate (1, &ptrs[inode->ind_idx]);
			//printf ("	@ inode_expand: indirect index is %d, target sector is %d\n", inode->ind_idx, ptrs[inode->ind_idx]);
			block_write(fs_device, ptrs[inode->ind_idx], init);
			inode->ind_idx ++;
			allocate_length += BLOCK_SECTOR_SIZE;
			left_sectors --;
			//printf ("	@ inode_expand: dir_idx is %d, length is %d, left sector is %d\n", inode->dir_idx, allocate_length, left_sectors);
			if (left_sectors == 0) {
				block_write(fs_device, inode->ptr[inode->dir_idx], ptrs);
				return length;
			}
		}
		block_write(fs_device, inode->ptr[inode->dir_idx], ptrs);
		inode->dir_idx ++;
		inode->ind_idx = 0;
	}
	block_sector_t ptrs2[INDIRECT_PTRS];
  	//printf("	@ inode_expand: dir_idx is %d, double indirect pointer sector is %d\n",inode->dir_idx, inode->ptr[inode->dir_idx]);

	ASSERT (inode->dir_idx == DIRECT_PTRS - 1);
	if (inode->double_ind_idx == 0) 
		free_map_allocate(1, &inode->ptr[inode->dir_idx]);
	block_read(fs_device, inode->ptr[inode->dir_idx], ptrs2);
	while (inode->double_ind_idx < INDIRECT_PTRS) {
  		//printf("	@ inode_expand: double_ind_idx is %d, block_read sector is %d\n",inode->double_ind_idx, ptrs2[inode->double_ind_idx]);
		if (inode->ind_idx == 0) 
			free_map_allocate(1, &ptrs2[inode->double_ind_idx]);
		block_read(fs_device, ptrs2[inode->double_ind_idx], ptrs);
		while (inode->ind_idx < INDIRECT_PTRS) {
			free_map_allocate (1, &ptrs[inode->ind_idx]);
			block_write(fs_device, ptrs[inode->ind_idx], init);
			inode->ind_idx ++;
			allocate_length += BLOCK_SECTOR_SIZE;
			left_sectors --;
			if (left_sectors == 0) {
				block_write (fs_device, ptrs2[inode->double_ind_idx], ptrs);
				block_write (fs_device, inode->ptr[inode->dir_idx], ptrs2);
				return length;
			}
		}
		block_write (fs_device, ptrs2[inode->double_ind_idx], ptrs);
		inode->double_ind_idx ++;
		inode->ind_idx = 0;
	}
	block_write (fs_device, inode->ptr[inode->dir_idx], ptrs2);
	return allocate_length;
}

/* free allocated area of inode */
void inode_free (struct inode *inode) {
	//printf("	@ inode_free: free is called, inode's sector is %d\n", inode->sector);
	block_sector_t ptrs[INDIRECT_PTRS];
	block_sector_t ptrs2[INDIRECT_PTRS];
	// release double-indirect blocks
	if (inode->dir_idx == DIRECT_PTRS) {
		inode->dir_idx--;
  		//printf("	@ inode_free: dir_idx is %d, block_read sector is %d\n",inode->dir_idx, inode->ptr[inode->dir_idx]);
		block_read(fs_device, inode->ptr[inode->dir_idx], ptrs2);
		while (inode->double_ind_idx > 0) {
			inode->double_ind_idx--;
  			//printf("	@ inode_free: double_ind_idx is %d, block_read sector is %d\n",inode->double_ind_idx, ptrs2[inode->double_ind_idx]);
			block_read(fs_device, ptrs2[inode->double_ind_idx], ptrs);
			while (inode->ind_idx > 0) 	{
				inode->ind_idx --;
				free_map_release (ptrs[inode->ind_idx], 1);
			}
			inode->ind_idx = INDIRECT_PTRS;
			free_map_release (ptrs2[inode->double_ind_idx], 1);
		}
		free_map_release (inode->ptr[inode->dir_idx], 1);
	}
	// release single-indirect blocks
	while (inode->dir_idx > DIRECT_BLOCKS) {
		inode->dir_idx--;
  		//printf("	@ inode_free: dir_idx is %d, block_read sector is %d\n",inode->dir_idx, inode->ptr[inode->dir_idx]);
		block_read(fs_device, inode->ptr[inode->dir_idx], ptrs);
		while (inode->ind_idx > 0) {
			inode->ind_idx --;
			free_map_release (ptrs[inode->ind_idx], 1);
		}
		inode->ind_idx = INDIRECT_PTRS;
		free_map_release (inode->ptr[inode->dir_idx], 1);
	}
	// release direct blocks
	while (inode->dir_idx > 0) {
		inode->dir_idx --;
		free_map_release (inode->ptr[inode->dir_idx], 1);
	}
	free_map_release (inode->sector, 1);
}
