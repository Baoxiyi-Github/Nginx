
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    //当前 cleanup 数据的回调函数
    ngx_pool_cleanup_pt   handler;      //是一个函数指针，指向一个可以释放data所对应资源的函数。该函数只有一个参数，就是data。 
    //内存的真正地址
    void                 *data;         //指明了该节点所对应的资源。
    //指向下一块 cleanup 内存的指针
    ngx_pool_cleanup_t   *next;         //指向该链表中下一个元素。
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;     //指向下一块large内存的指针
    void                 *alloc;    //真正的内存地址
};


typedef struct {
    u_char               *last;     //当前pool中用完的数据的结尾指针，即可用数据的开始指针
    u_char               *end;      //当前pool数据库的结尾指针
    ngx_pool_t           *next;     //指向下一个pool的指针
    ngx_uint_t            failed;   //当前pool内存不足以分配的次数
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;        //包含pool的数据去指针的结构体
    size_t                max;      //当前pool最大可分配的内存大小(Bytes)
    ngx_pool_t           *current;  //pool当前正在使用的pool的指针
    ngx_chain_t          *chain;    //pool当前可用的ngx_chain_t数据，注意：由ngx_free_chain赋值
    ngx_pool_large_t     *large;    //pool指向大数据块的指针（大数据块是指size>max的数据块）
    ngx_pool_cleanup_t   *cleanup;  // pool 中指向 ngx_pool_cleanup_t 数据块的指针
    ngx_log_t            *log;      //pool 中指向 ngx_log_t 的指针，用于写日志的
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
