
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void             *value;
    u_short           len;
    u_char            name[1];
} ngx_hash_elt_t;

/*
 *常用的解决冲突的方法有线性探测，二次探测和开链法等。
 *ngx_hash_t使用的是最常用的一种，也就是开链法，这也是STL中的hash表使用的方法
 *1.ngx_hash_t不像其他的hash表的实现，可以插入删除元素，它只能一次初始化，就构建起整个hash表以后，既不能再删除，也不能在插入元素了。
 *2.ngx_hash_t的开链并不是真的开了一个链表，实际上是开了一段连续的存储空间，几乎可以看做是一个数组。这是因为ngx_hash_t在初始化的时候，
 *会经历一次预计算的过程，提前把每个桶里面会有多少元素放进去给计算出来，这样就提前知道每个桶的大小了。那么就不需要使用链表，一段连续的
 *存储空间就足够了。这也从一定程度上节省了内存的使用。
 */
typedef struct {
    ngx_hash_elt_t  **buckets;
    ngx_uint_t        size;
} ngx_hash_t;


typedef struct {
    ngx_hash_t        hash;
    void             *value;
} ngx_hash_wildcard_t;


typedef struct {
    ngx_str_t         key;
    ngx_uint_t        key_hash;     //key_hash是对key使用hash函数计算出来的值
    void             *value;
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    ngx_hash_t            hash;
    ngx_hash_wildcard_t  *wc_head;
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


typedef struct {
    ngx_hash_t       *hash;         //该字段如果为NULL，那么调用完初始化函数后，该字段指向新创建出来的hash表。
                                    //如果该字段不为NULL，那么在初始的时候，所有的数据被插入了这个字段所指的hash表中。

    ngx_hash_key_pt   key;          //指向从字符串生成hash值的hash函数。nginx的源代码中提供了默认的实现函数ngx_hash_key_lc

    ngx_uint_t        max_size;     //hash表中的桶的个数。该字段越大，元素存储时冲突的可能性越小，每个桶中存储的元素会更少，则查询起来的速度更快。
                                    //当然，这个值越大，越造成内存的浪费也越大，(实际上也浪费不了多少)

    ngx_uint_t        bucket_size;  //每个桶的最大限制大小，单位是字节。如果在初始化一个hash表的时候，发现某个桶里面无法存的下所有属于该桶的元素，
                                    //则hash表初始化失败

    char             *name;         //该hash表的名字
    ngx_pool_t       *pool;         //该hash表分配内存使用的pool
    ngx_pool_t       *temp_pool;    //该hash表使用的临时pool，在初始化完成以后，该pool可以被释放和销毁掉
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    ngx_uint_t        hsize;

    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

    ngx_array_t       keys;
    ngx_array_t      *keys_hash;

    ngx_array_t       dns_wc_head;
    ngx_array_t      *dns_wc_head_hash;

    ngx_array_t       dns_wc_tail;
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
