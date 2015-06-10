
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts; //节点中存放具体元素的内存的开始地址
    ngx_uint_t        nelts;//节点中已有元素个数，不能大于 nalloc
    ngx_list_part_t  *next; //指向下一个节点
};


typedef struct {
    ngx_list_part_t  *last; //指向该链表的最后一个节点
    ngx_list_part_t   part; //指向该链表首个存放具体元素的节点
    size_t            size; //链表中存放的具体元素所需内存大小
    ngx_uint_t        nalloc;//每个节点所含的固定大小的数组的容量
    ngx_pool_t       *pool;  //该list使用的分配内存的pool   
} ngx_list_t;


//创建一个ngx_list_t类型的对象,并对该list的第一个节点分配存放元素的内存空间
//    pool:   分配内存使用的pool。  
//    n:  每个节点固定长度的数组的长度。  
//    size:   存放的具体元素的个数。
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
