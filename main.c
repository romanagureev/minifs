#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <ctype.h>

#define ptr uint8_t

#define NAME_LEN 256
#define DATA_BLOCK_LEN 1024

const char* DEFAULT_FS_PATH = "minifs";

#define UNUSED_TYPE 0
#define FILE_TYPE 1
#define DIR_TYPE 2
struct iNode {
   char name[NAME_LEN];
   uint32_t size;
   uint8_t type;
   ptr data_chunk_ptr;
};

#define DIR_CHUNK_LEN 7
struct dir_chunk {
  char name[DIR_CHUNK_LEN][NAME_LEN];
  ptr blocks[DIR_CHUNK_LEN];
  ptr next_chunk;
  uint8_t used;
};

#define FILE_CHUNK_LEN 6
struct file_chunk {
  ptr blocks[FILE_CHUNK_LEN];
  ptr next_chunk;
  uint8_t used;
};

struct super_block {
  struct iNode inodes[256];
  struct dir_chunk dir_chunk[256];
  struct file_chunk file_chunk[256];
};

#define INODE_SHIFT 0
#define DIR_CHUNK_SHIFT INODE_SHIFT + 256 * sizeof(struct iNode)
#define FILE_CHUNK_SHIFT DIR_CHUNK_SHIFT + 256 * sizeof(struct dir_chunk)
#define DATA_SHIFT FILE_CHUNK_SHIFT + 256 * sizeof(struct file_chunk)
#define DISK_SIZE DATA_SHIFT + 256 * DATA_BLOCK_LEN

struct context {
  struct super_block* super;
  char path[NAME_LEN];
  ptr current_node;
  int fd;
  void* mmaped;
};

struct iNode* get_inode(ptr i, struct context* ctx) {
  return ctx->mmaped + INODE_SHIFT + i * sizeof(struct iNode);
}

struct dir_chunk* get_dir_chunk(ptr i, struct context* ctx) {
  return ctx->mmaped + DIR_CHUNK_SHIFT + i * sizeof(struct dir_chunk);
}

struct file_chunk* get_file_chunk(ptr i, struct context* ctx) {
  return ctx->mmaped + FILE_CHUNK_SHIFT + i * sizeof(struct file_chunk);
}

char* get_data(ptr i, struct context* ctx) {
  return ctx->mmaped + DATA_SHIFT + i * DATA_BLOCK_LEN;
}

ptr get_new_inode(struct context* ctx) {
  for (int i = 1; i < 256; ++i) {
    if (ctx->super->inodes[i].type == UNUSED_TYPE) {
      return i;
    }
  }
  // Error
  return 0;
}

ptr get_new_dir_chunk(struct context* ctx) {
  for (int i = 1; i < 256; ++i) {
    if (ctx->super->dir_chunk[i].used == 0) {
      ctx->super->dir_chunk[i].used = 1;
      return i;
    }
  }
  // Error
  return 0;
}

ptr get_new_file_chunk(struct context* ctx) {
  for (int i = 1; i < 256; ++i) {
    if (ctx->super->file_chunk[i].used == 0) {
      ctx->super->file_chunk[i].used = 1;
      return i;
    }
  }
  // Error
  return 0;
}

ptr get_new_data_block(struct context* ctx) {
  for (int i = 0; i < 256; ++i) {
    if (get_data(i, ctx)[0] == 0) {
      get_data(i, ctx)[0] = 1;
      return i;
    }
  }
  // Error
  return 0;
}

void add_new_block_to_dir(ptr inode, const char* name, ptr block, struct context* ctx) {
  int i = 0;
  int size = get_inode(inode, ctx)->size++;
  struct dir_chunk* curr_dir_chunk = get_dir_chunk(get_inode(inode, ctx)->data_chunk_ptr, ctx);
  while (i < size) {
    if (i == DIR_CHUNK_LEN) {
      curr_dir_chunk = get_dir_chunk(curr_dir_chunk->next_chunk, ctx);
      size -= DIR_CHUNK_LEN;
      i = 0;
    }
    ++i;
  }
  if (i == DIR_CHUNK_LEN) {
    curr_dir_chunk->next_chunk = get_new_dir_chunk(ctx);
    curr_dir_chunk = get_dir_chunk(curr_dir_chunk->next_chunk, ctx);
    i = 0;
  }
  strcpy(curr_dir_chunk->name[i], name);
  curr_dir_chunk->blocks[i] = block;
}

int find(ptr inode, const char* name, struct context* ctx) {
  int i = 0;
  int size = get_inode(inode, ctx)->size;
  struct dir_chunk* curr_dir_chunk = get_dir_chunk(get_inode(inode, ctx)->data_chunk_ptr, ctx);
  while (i < size) {
    if (i == DIR_CHUNK_LEN) {
      curr_dir_chunk = get_dir_chunk(curr_dir_chunk->next_chunk, ctx);
      size -= DIR_CHUNK_LEN;
      i = 0;
    }
    if (strcmp(curr_dir_chunk->name[i], name) == 0) {
      return curr_dir_chunk->blocks[i];
    }
    ++i;
  }
  return -1;
}

// root is inode[0]
void create_root(struct context* ctx) {
  struct iNode* inode = get_inode(0, ctx);
  inode->name[0] = '/';
  inode->size = 0;
  inode->type = DIR_TYPE;
  inode->data_chunk_ptr = get_new_dir_chunk(ctx);
  add_new_block_to_dir(0, ".", 0, ctx);
  add_new_block_to_dir(0, "..", 0, ctx);
}

struct context* init(const char* file_for_fs) {
  if (file_for_fs == NULL) {
    file_for_fs = DEFAULT_FS_PATH;
  }
  struct context* ctx = malloc(sizeof(struct context));
  memset(ctx, 0, sizeof(struct context));
  ctx->path[0] = '/';
  ctx->current_node = 0;
  if (access(file_for_fs, F_OK) == 0) {
    ctx->fd = open(file_for_fs, O_RDWR);
    ctx->mmaped = mmap(NULL, DISK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
    ctx->super = ctx->mmaped;
    return ctx;
  }
  ctx->fd = open(file_for_fs, O_RDWR|O_CREAT);
  ftruncate(ctx->fd, 0);
  ftruncate(ctx->fd, DISK_SIZE);
  ctx->mmaped = mmap(NULL, DISK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
  ctx->super = ctx->mmaped;
  create_root(ctx);
  return ctx;
}

void close_fs(struct context* ctx) {
  munmap(ctx->mmaped, DISK_SIZE);
  close(ctx->fd);
  free(ctx);
}

void ls(struct context* ctx) {
  int i = 0;
  int size = get_inode(ctx->current_node, ctx)->size;
  struct dir_chunk* curr_dir_chunk = get_dir_chunk(get_inode(ctx->current_node, ctx)->data_chunk_ptr, ctx);
  while (i < size) {
    if (i == DIR_CHUNK_LEN) {
      curr_dir_chunk = get_dir_chunk(curr_dir_chunk->next_chunk, ctx);
      size -= DIR_CHUNK_LEN;
      i = 0;
    }
    printf("%s\n", curr_dir_chunk->name[i]);
    ++i;
  }
}

// 0 if error, else len of read
int cd1(struct context* ctx, char* where) {
  char path[NAME_LEN];
  sscanf(where, "%[^/]/", path);
  int next = find(ctx->current_node, path, ctx);
  if (next == -1) {
    return 0;
  }
  struct iNode* next_inode = get_inode(next, ctx);
  if (next_inode->type == DIR_TYPE) {
    if (strcmp(path, ".") != 0) {
      if (strcmp(path, "..") != 0) {
        strcat(ctx->path, path);
        strcat(ctx->path, "/");
      } else {
        size_t len = strlen(ctx->path);
        if (len > 1) {
          do {
            ctx->path[len - 1] = '\0';
            --len;
          } while (ctx->path[len - 1] != '/');
        }
      }
    }
    ctx->current_node = next;
    return strlen(path) + 1;
  } else {
    printf("'%s' is not a directory.\n", path);
    return strlen(where);
  }
}

int cd(struct context* ctx, char* where) {
  if (where[0] == '/') {
    ctx->current_node = 0;
    ++where;
  }
  size_t len = strlen(where);
  int i = 0;
  while (i < len) {
    int moved = cd1(ctx, where + i);
    if (moved == 0) {
      return 0;
    }
    i += moved;
  }
  return 1;
}

void touch(struct context* ctx, const char* filename) {
  if (find(ctx->current_node, filename, ctx) != -1) {
    printf("File already exists!\n");
    return;
  }
  ptr inode_ptr = get_new_inode(ctx);
  struct iNode* inode = get_inode(inode_ptr, ctx);
  strcpy(inode->name, filename);
  inode->size = 0;
  inode->type = FILE_TYPE;
  inode->data_chunk_ptr = get_new_file_chunk(ctx);
  add_new_block_to_dir(ctx->current_node, filename, inode_ptr, ctx);
}

void mkdir(struct context* ctx, const char* dirname) {
  if (find(ctx->current_node, dirname, ctx) != -1) {
    printf("Directory already exists!\n");
    return;
  }
  ptr inode_ptr = get_new_inode(ctx);
  struct iNode* inode = get_inode(inode_ptr, ctx);
  strcpy(inode->name, dirname);
  inode->size = 0;
  inode->type = DIR_TYPE;
  inode->data_chunk_ptr = get_new_dir_chunk(ctx);
  add_new_block_to_dir(inode_ptr, ".", inode_ptr, ctx);
  add_new_block_to_dir(inode_ptr, "..", ctx->current_node, ctx);
  add_new_block_to_dir(ctx->current_node, dirname, inode_ptr, ctx);
}

void append(struct context* ctx, const char* filename, const char* data) {
  int inode = find(ctx->current_node, filename, ctx);
  if (inode == -1) {
    printf("No such file.\n");
    return;
  }
  int i = 0;
  int size = get_inode(inode, ctx)->size;
  struct file_chunk* curr_file_chunk = get_file_chunk(get_inode(inode, ctx)->data_chunk_ptr, ctx);
  while ((i + 1) * (DATA_BLOCK_LEN - 1) < size) {
    if (i == FILE_CHUNK_LEN) {
      curr_file_chunk = get_file_chunk(curr_file_chunk->next_chunk, ctx);
      size -= (DATA_BLOCK_LEN - 1) * FILE_CHUNK_LEN;
      i = 0;
    }
    ++i;
  }
  if ((i + 1) * (DATA_BLOCK_LEN - 1) == size) {
    ++i;
  }

  int written = 0;
  int data_len = strlen(data);
  while (written < data_len) {
    if (i == FILE_CHUNK_LEN) {
      curr_file_chunk = get_file_chunk(get_new_file_chunk(ctx), ctx);
      size -= (DATA_BLOCK_LEN - 1) * FILE_CHUNK_LEN;
      i = 0;
    }

    int to_copy = DATA_BLOCK_LEN - 1;
    int from = 1;
    if (i * (DATA_BLOCK_LEN - 1) < size) {
      to_copy = DATA_BLOCK_LEN - 1 - (size - i * (DATA_BLOCK_LEN - 1));
      from = 1 + size - i * (DATA_BLOCK_LEN - 1);
    } else {
      curr_file_chunk->blocks[i] = get_new_data_block(ctx);
    }
    if (to_copy > strlen(data + written)) {
      to_copy = strlen(data + written);
    }
    strncpy(get_data(curr_file_chunk->blocks[i], ctx) + from, data + written, to_copy);
    written += to_copy;
    ++i;
  }
  get_inode(inode, ctx)->size += written;
}

void cat(struct context* ctx, const char* filename) {
  int inode = find(ctx->current_node, filename, ctx);
  if (inode == -1) {
    printf("No such file.\n");
    return;
  }
  int i = 0;
  int size = get_inode(inode, ctx)->size;
  struct file_chunk* curr_file_chunk = get_file_chunk(get_inode(inode, ctx)->data_chunk_ptr, ctx);
  while (i * (DATA_BLOCK_LEN - 1) < size) {
    if (i == FILE_CHUNK_LEN) {
      curr_file_chunk = get_file_chunk(curr_file_chunk->next_chunk, ctx);
      size -= (DATA_BLOCK_LEN - 1) * FILE_CHUNK_LEN;
      i = 0;
    }

    printf("%s", get_data(curr_file_chunk->blocks[i], ctx) + 1);
    ++i;
  }
}


void show_usage() {
  printf("Usage:\n"
         "\tls\n"
         "\tcd <directory>\n"
         "\ttouch <filename>\n"
         "\tmkdir <directory>\n"
         "\tappend <filename> \"<data>\"\n"
         "\tappend_new_line <filename>\n"
         "\tcat <filename>\n"
         "\texit\n");
}

uint8_t check_path(char* path) {
  for (int i = 0; path[i] != '\0'; ++i) {
    if (isspace(path[i])) {
      return 0;
    }
  }
  return 1;
}

uint8_t check_filename(char* filename) {
  if (strlen(filename) == 0) {
    return 0;
  }
  for (int i = 0; filename[i] != '\0'; ++i) {
    if (isspace(filename[i]) || filename[i] == '/') {
      return 0;
    }
  }
  return 1;
}

uint8_t execute(const char* line, struct context* ctx) {
  if (strncmp(line, "ls", 2) == 0) {
    ls(ctx);
  } else if (strncmp(line, "cd ", 3) == 0) {
    char path[NAME_LEN];
    sscanf(line, "%*s %s", path);
    if (!check_path(path)) {
      printf("Incorrect path!\n");
    } else {
      if (!cd(ctx, path)) {
        printf("Wrong path.\n");
      }
    }
  } else if (strncmp(line, "touch ", 6) == 0) {
    char filename[NAME_LEN];
    sscanf(line, "%*s %s", filename);
    if (!check_filename(filename)) {
      printf("Incorrect filename!\n");
    } else {
      touch(ctx, filename);
    }
  } else if (strncmp(line, "mkdir ", 6) == 0) {
    char dirname[NAME_LEN];
    sscanf(line, "%*s %s", dirname);
    if (!check_filename(dirname)) {
      printf("Incorrect dirname!\n");
    } else {
      mkdir(ctx, dirname);
    }
  } else if (strncmp(line, "append ", 7) == 0) {
    char filename[NAME_LEN];
    char data[4096];
    sscanf(line, "%*s %s %[^\n]", filename, data);
    if (!check_filename(filename)) {
      printf("Incorrect filename!\n");
    } else {
      append(ctx, filename, data);
    }
  } else if (strncmp(line, "append_new_line ", 16) == 0) {
    char filename[NAME_LEN];
    sscanf(line, "%*s %s", filename);
    if (!check_filename(filename)) {
      printf("Incorrect filename!\n");
    } else {
      append(ctx, filename, "\n");
    }
  } else if (strncmp(line, "cat ", 4) == 0) {
    char filename[NAME_LEN];
    sscanf(line, "%*s %s", filename);
    if (!check_filename(filename)) {
      printf("Incorrect filename!\n");
    } else {
      cat(ctx, filename);
    }
  } else if (strcmp(line, "exit") == 0) {
    return 0;
  } else if (strncmp(line, "usage", 5) == 0) {
    show_usage();
  } else {
    printf("Unknown command. Print usage to show usage.\n");
  }
  return 1;
}

void run(struct context* ctx) {
  show_usage();
  size_t len = 1024;
  char* buffer = malloc(len);
  int i = 0;
  printf("minifs%s> ", ctx->path);
  while ((i = getline(&buffer, &len, stdin)) != -1) {
    if (i > 0 && isspace(buffer[i - 1])) {
      buffer[i - 1] = '\0';
      --i;
    }
    if (!execute(buffer, ctx)) {
      break;
    }
    memset(buffer, 0, len);
    printf("\n");
    printf("minifs:%s> ", ctx->path);
  }
  free(buffer);
}

int main(int argc, char* argv[]) {
  char* file_for_fs = NULL;
  if (argc > 1) {
    file_for_fs = argv[1];
  }
  struct context* ctx = init(file_for_fs);
  run(ctx);
  close_fs(ctx);
  return 0;
}
