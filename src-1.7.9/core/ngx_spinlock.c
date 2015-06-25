
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


//lock参数就是原子变量表达的锁，为0时表示锁是被释放的，非0表示锁已经被某个进程持有了
//value参数就是当锁没有被任何进程持有时（lock为0时），把lock设为value值时，表示当前进程持有了锁
//spin参数表示在多处理器系统内，当ngx_spinlock没由拿到锁时，当前进程在内核的一次调度中，该方法等待其他处理器释放锁的时间
void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        //多处理器系统下
        if (ngx_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }

                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        ngx_sched_yield();//目的都是暂时“让出”处理器
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
