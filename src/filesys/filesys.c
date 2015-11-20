#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"

#define SLASH 47

/* Partition that contains the file system. */
struct block *fs_device;
struct lock lock;

static void do_format (void);
struct dir* parse_dir (const char* path);
char* parse_file (const char* path);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  
  cache_init ();
  inode_init ();
  //lock_init (&lock);
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  write_back_cache_list(true);
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  if (strlen(name) == 0) return false;
  //lock_acquire(&lock);
  block_sector_t inode_sector = 0;
  struct dir *dir = parse_dir(name);
  char* fname = parse_file(name);
  bool success = false;

  if(strcmp(fname, ".") != 0 && strcmp(fname, "..") != 0){	  
	 success = (dir != NULL
               && free_map_allocate (1, &inode_sector)
               && inode_create (inode_sector, initial_size, is_dir)
               && dir_add (dir, fname, inode_sector));
  }

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  //printf("		@ success for %s = %d\n", fname, success);

  free(fname);
  //lock_release(&lock);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (strlen(name) == 0) return NULL;
  //lock_acquire(&lock);
  struct inode *inode = NULL;
  struct dir *dir = parse_dir(name);
  char* fname = parse_file(name);
  
  if (dir != NULL){
	  if (strcmp(fname, "..") == 0){
		  if(!getParentDIR(dir, &inode)){
			  free(fname);
	//		  lock_release(&lock);
			  return NULL;
		  }
 	  }
	  else if(strcmp(fname, ".") == 0 || (isRootDIR(dir) && strlen(fname) == 0)){
		  free(fname);
	//	  lock_release(&lock);
		  return (struct file *) dir;
	  }
	  else{
   	 	if(!dir_lookup (dir, fname, &inode)){
  		printf("		@ wow\n");
			free(fname);
	//		lock_release(&lock);
			return NULL;
		}
	  }
  }
  else {
	//  lock_release(&lock);
	  return NULL;
  }

  dir_close (dir);
  if (fname) free(fname);
  //lock_release(&lock);

  if(getProperty(inode) == DIR)
	  return (struct file *) dir_open(inode);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{ 
  //lock_acquire(&lock);
  struct dir *dir = parse_dir(name);
  char* fname = parse_file(name);
  bool success = dir != NULL && dir_remove(dir, fname);

  dir_close (dir); 
  free(fname);
  //lock_release(&lock);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

struct dir* parse_dir (const char* path)
{
	char copy[strlen(path) + 1];
	memcpy(copy, path, strlen(path) + 1);

	struct dir *dir;
	char *temp = NULL;
	char *next_token = NULL;
	struct inode *inode = NULL;

	// if first path name "/" or active directory is null, go to root
	if(copy[0] == SLASH || !thread_current()->stage) dir = dir_open_root();
	else dir = dir_reopen(thread_current()->stage);

	char *token = strtok_r(copy, "/", &temp);
	if(token) next_token = strtok_r(NULL, "/", &temp);
	for(; next_token != NULL; next_token = strtok_r(NULL, "/", &temp)){
		if(strcmp(token, ".") != 0){
			//printf("		@ parsed dir name = %s\n", token);
			if(strcmp(token, "..") == 0){
				if(!getParentDIR(dir, &inode)) return NULL;}
			else{
				if(!dir_lookup(dir, token, &inode)) return NULL;}

			dir_close(dir);
			dir = dir_open(inode);
		}		
		token = next_token;
	}

	return dir;
}

char* parse_file(const char* path)
{
	//printf("	@ parse_file, path = %s\n",path);
	char copy[strlen(path) + 1];
	memcpy(copy, path, strlen(path) + 1);

	struct dir *dir;
	char *temp = NULL;
	char *prev_token = NULL;

	char *token = strtok_r(copy, "/", &temp);
	for(; token != NULL; token = strtok_r(NULL, "/", &temp)){
		prev_token = token;
	}

	char *name = malloc(strlen(prev_token) + 1);
	memcpy(name, prev_token, strlen(prev_token) + 1);
	return name;
}

bool filesys_chdir(const char* name)
{
  if (strlen(name) == 0) return false;
  struct inode *inode = NULL;
  struct dir *dir = parse_dir(name);
  char* fname = parse_file(name);

//  printf("		@ filesys_chdir, dir = %s\n",dir);
//  printf("		@ filesys_chdir, fname = %s\n",fname);

  if(dir != NULL){
	  if (strcmp(fname, "..") == 0){
		  //free(fname);
		  if(!getParentDIR(dir, &inode)){
			  free(fname);
			  return false;
		  }
 	  }
	  else if(strcmp(fname, ".") == 0){
		  free(fname);
		  return true;
	  }
	  else if(isRootDIR(dir) && strlen(fname) == 0){
		  free(fname);
		  dir_close( thread_current() -> stage);
		  thread_current() -> stage = dir;
		  return true;
	  }
	  else{
   	 	if(!dir_lookup (dir, fname, &inode)){
			free(fname);
			return false;
		}
	  }
  }
  else return false;

  dir_close(dir);
  free(fname);

  dir = dir_open(inode);
  if(dir != NULL){
	  dir_close(thread_current() -> stage);
	  thread_current() -> stage = dir;
	  dir_close(dir);
	  return true;
  }

  return false;
}
