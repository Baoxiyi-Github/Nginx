
//nginx的启动过程代码主要分布在src/core以及src/os/unix目录下。
//启动流程的函数调用序列：
//main(src/core/nginx.c)→ngx_init_cycle(src/core/ngx_cycle.c)→ngx_master_process_cycle(src/os/)。
//nginx的启动过程就是围绕着这三个函数进行的
int ngx_cdecl
main(int argc, char *const *argv)
{
    ngx_int_t         i;
    ngx_log_t        *log;
    ngx_cycle_t      *cycle, init_cycle;
    ngx_core_conf_t  *ccf;

    ngx_debug_init();//与平台相关函数，什么也没有做
#define ngx_debug_init()

    if (ngx_strerror_init() != NGX_OK) {//初始化NGX的错误信息，从标准系统copy 
        return 1;
    }
    //将所有错误提示信息预先存储在一个数组里，而预先确定这个数组的大小，
    //是在自动化auto/unix脚本完成.
    ngx_int_t ngx_strerror_init(void)
    {
        char       *msg;
        u_char     *p;
        size_t      len;
        ngx_err_t   err;

        /*
         * ngx_strerror() is not ready to work at this stage, therefore,
         * malloc() is used and possible errors are logged using strerror().
         */
        /*
         *linux---->#define NGX_SYS_NERR  135
         *所有 strerror 消息的数量所需要的 ngx_str_t 的内存字节数
         *（注意不是消息本身，因为小内容是存在 ngx_str_t 的 data 里的）
         */
        len = NGX_SYS_NERR * sizeof(ngx_str_t);

        ngx_sys_errlist = malloc(len);
        if (ngx_sys_errlist == NULL) {
            goto failed;
        }

        for (err = 0; err < NGX_SYS_NERR; err++) {
            msg = strerror(err);
            len = ngx_strlen(msg);

            p = malloc(len);
            if (p == NULL) {
                goto failed;
            }

            ngx_memcpy(p, msg, len);
            ngx_sys_errlist[err].len = len;
            ngx_sys_errlist[err].data = p;
        }

        return NGX_OK;

failed:

        err = errno;
        ngx_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

        return NGX_ERROR;
    }

    if (ngx_get_options(argc, argv) != NGX_OK) {//获取命令行参数
        return 1;
    }

    /*
     *传入的是 main 函数的两个参数 argc 和 argv
     *Options:
     *  -?,-h         : this help
     *  -v            : show version and exit
     *  -V            : show version and configure options then exit
     *  -t            : test configuration and exit
     *  -q            : suppress non-error messages during configuration testing
     *  -s signal     : send signal to a master process: stop, quit, reopen, reload
     *  -p prefix     : set prefix path (default: /usr/local/nginx/)
     *  -c filename   : set configuration file (default: conf/nginx.conf)
     *  -g directives : set global directives out of configuration file
     */
    static ngx_int_t ngx_get_options(int argc, char *const *argv)
    {
        u_char     *p;
        ngx_int_t   i;

        //对于每一个 argv（注意是从 1 开始，因为 0 是 "nginx"）
        for (i = 1; i < argc; i++) {

            //// p 为第 i 个参数的地址
            p = (u_char *) argv[i];

            if (*p++ != '-') {
                ngx_log_stderr(0, "invalid option: \"%s\"", argv[i]);
                return NGX_ERROR;
            }
            //之所以 while 循环是因为一个减号可以带过个参数，比如 -hV
            while (*p) {

                // 注意 p 被加 1
                switch (*p++) {

                    // 问号和 h 都是显示帮助信息和版本信息
                    case '?':
                    case 'h':
                        ngx_show_version = 1;
                        ngx_show_help = 1;
                        break;

                        // 小 v 显示版本信息
                    case 'v':
                        ngx_show_version = 1;
                        break;

                        // 大 v 显示版本信息和配置信息
                    case 'V':
                        ngx_show_version = 1;
                        ngx_show_configure = 1;
                        break;

                        // t 用于测试配置文件
                    case 't':
                        ngx_test_config = 1;
                        break;

                        // q 表示安静模式
                    case 'q':
                        ngx_quiet_mode = 1;
                        break;

                        // p 为指定 prefix path
                    case 'p':
                        if (*p) {
                            ngx_prefix = p;
                            goto next;
                        }

                        if (argv[++i]) {
                            ngx_prefix = (u_char *) argv[i];
                            goto next;
                        }

                        ngx_log_stderr(0, "option \"-p\" requires directory name");
                        return NGX_ERROR;

                        // 使用指定的配置文件
                    case 'c':
                        if (*p) {
                            ngx_conf_file = p;
                            goto next;
                        }

                        if (argv[++i]) {
                            ngx_conf_file = (u_char *) argv[i];
                            goto next;
                        }

                        ngx_log_stderr(0, "option \"-c\" requires file name");
                        return NGX_ERROR;

                        // 在配置文件之外设置全局指令
                    case 'g':
                        if (*p) {
                            ngx_conf_params = p;
                            goto next;
                        }

                        if (argv[++i]) {
                            ngx_conf_params = (u_char *) argv[i];
                            goto next;
                        }

                        ngx_log_stderr(0, "option \"-g\" requires parameter");
                        return NGX_ERROR;

                        // s 为 signal，即给 Nginx 发送信号
                    case 's':
                        if (*p) {// 下一个参数紧跟在 -s 后，比如 -sstop
                            ngx_signal = (char *) p;

                        } else if (argv[++i]) {// 下一个参数
                            ngx_signal = argv[i];

                        } else {// -s 没有带参数时
                            ngx_log_stderr(0, "option \"-s\" requires parameter");
                            return NGX_ERROR;
                        }

                        // 四个信号分别对应：停止、退出、重新打开文件（日志文件等）、重新加载配置文件
                        if (ngx_strcmp(ngx_signal, "stop") == 0
                                    || ngx_strcmp(ngx_signal, "quit") == 0
                                    || ngx_strcmp(ngx_signal, "reopen") == 0
                                    || ngx_strcmp(ngx_signal, "reload") == 0)
                        {
                            ngx_process = NGX_PROCESS_SIGNALLER;
                            goto next;
                        }

                        ngx_log_stderr(0, "invalid option: \"-s %s\"", ngx_signal);
                        return NGX_ERROR;

                    default:
                        ngx_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
                        return NGX_ERROR;
                }
            }

next:

            continue;
        }

        return NGX_OK;
    }

    if (ngx_show_version) {//显示版本，帮助，配置，测试等信息
        ngx_write_stderr("nginx version: " NGINX_VER_BUILD NGX_LINEFEED);

        if (ngx_show_help) {
            ngx_write_stderr(
                        "Usage: nginx [-?hvVtq] [-s signal] [-c filename] "
                        "[-p prefix] [-g directives]" NGX_LINEFEED
                        NGX_LINEFEED
                        "Options:" NGX_LINEFEED
                        "  -?,-h         : this help" NGX_LINEFEED
                        "  -v            : show version and exit" NGX_LINEFEED
                        "  -V            : show version and configure options then exit"
                        NGX_LINEFEED
                        "  -t            : test configuration and exit" NGX_LINEFEED
                        "  -q            : suppress non-error messages "
                        "during configuration testing" NGX_LINEFEED
                        "  -s signal     : send signal to a master process: "
                        "stop, quit, reopen, reload" NGX_LINEFEED
#ifdef NGX_PREFIX
                        "  -p prefix     : set prefix path (default: "
                        NGX_PREFIX ")" NGX_LINEFEED
#else
                        "  -p prefix     : set prefix path (default: NONE)" NGX_LINEFEED
#endif
                        "  -c filename   : set configuration file (default: "
                        NGX_CONF_PATH ")" NGX_LINEFEED
                        "  -g directives : set global directives out of configuration "
                        "file" NGX_LINEFEED NGX_LINEFEED
                        );
        }

        if (ngx_show_configure) {
            ngx_write_stderr(
#ifdef NGX_COMPILER
                        "built by " NGX_COMPILER NGX_LINEFEED
#endif
#if (NGX_SSL)
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
                        "TLS SNI support enabled" NGX_LINEFEED
#else
                        "TLS SNI support disabled" NGX_LINEFEED
#endif
#endif
                        "configure arguments:" NGX_CONFIGURE NGX_LINEFEED);
        }

        if (!ngx_test_config) {
            return 0;
        }
    }

    /* TODO */ ngx_max_sockets = -1;

    ngx_time_init(); //初始化时间并同步内存.初始化并更新时间，如全局变量ngx_cached_time

    void    ngx_time_init(void)
    {
        //用于记录错误日志时间，http缓存时间，http缓存log时间级iso8061时间，初始化过程中，先计算该时间表示的字符串的长度，这样可以省却在用到的时候再进行计算。
        //ngx_cached_time是nginx时间类型的数据结构，他是volatile类型的，即防止编译器优化，每次都要从内存中读取，而不是用缓存值
        ngx_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
        ngx_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
        ngx_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;
        ngx_cached_http_log_iso8601.len = sizeof("1970-09-28T12:00:00+06:00") - 1;
        ngx_cached_syslog_time.len = sizeof("Sep 28 12:00:00") - 1;

        ngx_cached_time = &cached_time[0];

        ngx_time_update();//用于更新系统时间
        void ngx_time_update(void)
        {
            u_char          *p0, *p1, *p2, *p3, *p4;
            ngx_tm_t         tm, gmt;
            time_t           sec;
            ngx_uint_t       msec;
            ngx_time_t      *tp;
            struct timeval   tv;

            if (!ngx_trylock(&ngx_time_lock)) {//获取时间更新的互斥锁，避免进程或线程间并发更新系统时间
                /*#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))*/
                /*这里判断*lock为0，表示没有被枷锁，并对其进行原子操作加锁ngx_atomic_cmp_set，设置其值为1*/

                /*
                 * "cmpxchgl  r, [m]":
                 *
                 *     if (eax == [m]) {
                 *         zf = 1;
                 *         [m] = r;
                 *     } else {
                 *         zf = 0;
                 *         eax = [m];
                 *     }
                 *
                 *
                 * The "r" means the general register.
                 * The "=a" and "a" are the %eax register.
                 * Although we can return result in any register, we use "a" because it is
                 * used in cmpxchgl anyway.  The result is actually in %al but not in %eax,
                 * however, as the code is inlined gcc can test %al as well as %eax,
                 * and icc adds "movzbl %al, %eax" by itself.
                 *
                 * The "cc" means that flags were changed.
                 */

                //通过嵌入式汇编的方式，进行加锁并原子设定lock的值为1
                static ngx_inline ngx_atomic_uint_t
                    ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
                                ngx_atomic_uint_t set)
                    {
                        u_char  res;

                        __asm__ volatile (

                                    NGX_SMP_LOCK
                                    "    cmpxchgl  %3, %1;   "
                                    "    sete      %0;       "

                                    : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");

                        return res;
                    }

                return;
            }

            ngx_gettimeofday(&tv);//此处为系统标准函数，获取系统时间，存储到tv变量中
            /*#define ngx_gettimeofday(tp)  (void) gettimeofday(tp, NULL);*/

            sec = tv.tv_sec;
            msec = tv.tv_usec / 1000;

            ngx_current_msec = (ngx_msec_t) sec * 1000 + msec;

            tp = &cached_time[slot];

            //如果系统缓存的时间秒和当前更新的秒值未发生变化，则只需更新毫秒值，然后返回，否则认为系统长时间未更新时间，继续往后执行
            if (tp->sec == sec) {
                tp->msec = msec;
                ngx_unlock(&ngx_time_lock);
                return;
            }

            if (slot == NGX_TIME_SLOTS - 1) {
                slot = 0;
            } else {
                slot++;
            }

            tp = &cached_time[slot];

            tp->sec = sec;
            tp->msec = msec;

            ngx_gmtime(sec, &gmt);//将时间换算为天、小时、分、秒具体实现比较简单

            void ngx_gmtime(time_t t, ngx_tm_t *tp)
            {
                ngx_int_t   yday;
                ngx_uint_t  n, sec, min, hour, mday, mon, year, wday, days, leap;

                /* the calculation is valid for positive time_t only */

                n = (ngx_uint_t) t;

                days = n / 86400;

                /* January 1, 1970 was Thursday */

                wday = (4 + days) % 7;

                n %= 86400;
                hour = n / 3600;
                n %= 3600;
                min = n / 60;
                sec = n % 60;

                /*
                 * the algorithm based on Gauss' formula,
                 * see src/http/ngx_http_parse_time.c
                 */

                /* days since March 1, 1 BC */
                days = days - (31 + 28) + 719527;

                /*
                 * The "days" should be adjusted to 1 only, however, some March 1st's go
                 * to previous year, so we adjust them to 2.  This causes also shift of the
                 * last February days to next year, but we catch the case when "yday"
                 * becomes negative.
                 */

                year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

                yday = days - (365 * year + year / 4 - year / 100 + year / 400);

                if (yday < 0) {
                    leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
                    yday = 365 + leap + yday;
                    year--;
                }

                /*
                 * The empirical formula that maps "yday" to month.
                 * There are at least 10 variants, some of them are:
                 *     mon = (yday + 31) * 15 / 459
                 *     mon = (yday + 31) * 17 / 520
                 *     mon = (yday + 31) * 20 / 612
                 */

                mon = (yday + 31) * 10 / 306;

                /* the Gauss' formula that evaluates days before the month */

                mday = yday - (367 * mon / 12 - 30) + 1;

                if (yday >= 306) {

                    year++;
                    mon -= 10;

                    /*
                     * there is no "yday" in Win32 SYSTEMTIME
                     *
                     * yday -= 306;
                     */

                } else {

                    mon += 2;

                    /*
                     * there is no "yday" in Win32 SYSTEMTIME
                     *
                     * yday += 31 + 28 + leap;
                     */
                }

                tp->ngx_tm_sec = (ngx_tm_sec_t) sec;
                tp->ngx_tm_min = (ngx_tm_min_t) min;
                tp->ngx_tm_hour = (ngx_tm_hour_t) hour;
                tp->ngx_tm_mday = (ngx_tm_mday_t) mday;
                tp->ngx_tm_mon = (ngx_tm_mon_t) mon;
                tp->ngx_tm_year = (ngx_tm_year_t) year;
                tp->ngx_tm_wday = (ngx_tm_wday_t) wday;
            }

            p0 = &cached_http_time[slot][0];

            (void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                        week[gmt.ngx_tm_wday], gmt.ngx_tm_mday,
                        months[gmt.ngx_tm_mon - 1], gmt.ngx_tm_year,
                        gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec);

#if (NGX_HAVE_GETTIMEZONE)

            tp->gmtoff = ngx_gettimezone();//需要计算时区
            ngx_gmtime(sec + tp->gmtoff * 60, &tm);

#elif (NGX_HAVE_GMTOFF)

            ngx_localtime(sec, &tm);//计算本地系统时间与时区
            cached_gmtoff = (ngx_int_t) (tm.ngx_tm_gmtoff / 60);
            tp->gmtoff = cached_gmtoff;

#else

            ngx_localtime(sec, &tm);//直接计算本地系统时间
            cached_gmtoff = ngx_timezone(tm.ngx_tm_isdst);
            tp->gmtoff = cached_gmtoff;

#endif


            p1 = &cached_err_log_time[slot][0];

            (void) ngx_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
                        tm.ngx_tm_year, tm.ngx_tm_mon,
                        tm.ngx_tm_mday, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec);


            p2 = &cached_http_log_time[slot][0];

            (void) ngx_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
                        tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                        tm.ngx_tm_year, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec,
                        tp->gmtoff < 0 ? '-' : '+',
                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

            p3 = &cached_http_log_iso8601[slot][0];

            (void) ngx_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d",
                        tm.ngx_tm_year, tm.ngx_tm_mon,
                        tm.ngx_tm_mday, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec,
                        tp->gmtoff < 0 ? '-' : '+',
                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

            p4 = &cached_syslog_time[slot][0];

            (void) ngx_sprintf(p4, "%s %2d %02d:%02d:%02d",
                        months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
                        tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

            //一个应用层设置内存屏障的函数，表示上述片段已经计算完毕，需要完成内存的同步，然后在后续的几步操作中，实现对初始化最初的几个全局变量的赋值操作。这里再次看到，没有字符串长度的计算，nginx通过初始化一次长度计算从而一劳永逸，而不用每次计算时再去纠结字符串的长度问题。这一点比起apache来说，确实优化不少.
            ngx_memory_barrier();

            ngx_cached_time = tp;
            ngx_cached_http_time.data = p0;
            ngx_cached_err_log_time.data = p1;
            ngx_cached_http_log_time.data = p2;
            ngx_cached_http_log_iso8601.data = p3;
            ngx_cached_syslog_time.data = p4;

            ngx_unlock(&ngx_time_lock);
        }
    }



#if (NGX_PCRE)
    ngx_regex_init(); //初始化正在表达式
    //pcre主要是用来支持URL Rewrite的，URL Rewrite主要是为了满足代理模式下，对请求访问的URL地址进行rewrite操作，来实现定向访问.
    void ngx_regex_init(void)
    {
        //Pcre的初始化操作，主要是初始化处理pcre正则时的内存分配和释放，因此其赋值操作也仅是两个内存操作
        pcre_malloc = ngx_regex_malloc;
        pcre_free = ngx_regex_free;
    }
#endif

    ngx_pid = ngx_getpid();// 获取进程ID
    // #define ngx_getpid   getpid

    log = ngx_log_init(ngx_prefix);//初始化日志，如初始化全局变量ngx_prefix，打开日志文件ngx_log_file.fd
    if (log == NULL) {
        return 1;
    }

    ngx_log_t *
        ngx_log_init(u_char *prefix)
        {
            u_char  *p, *name;
            size_t   nlen, plen;

            ngx_log.file = &ngx_log_file;//此处初始化log中的file字段存储全局变量ngx_log_file的地址
            ngx_log.log_level = NGX_LOG_NOTICE;

            name = (u_char *) NGX_ERROR_LOG_PATH;//这里名字初始化为error日志文件路径，默认定义为（objs/ngx_auto_config.h.

            /*
             * we use ngx_strlen() here since BCC warns about
             * condition is always false and unreachable code
             */

            nlen = ngx_strlen(name);

            if (nlen == 0) {
                ngx_log_file.fd = ngx_stderr;
                return &ngx_log;
            }

            p = NULL;

#if (NGX_WIN32)
            if (name[1] != ':') {
#else
                if (name[0] != '/') {
#endif
                }
                if (prefix) {
                    plen = ngx_strlen(prefix);

                } else {
#ifdef NGX_PREFIX
                    prefix = (u_char *) NGX_PREFIX;
                    plen = ngx_strlen(prefix);
#else
                    plen = 0;
#endif
                }
                //主要分配内存，来存储log文件名，prefix为指定的路径前缀。初始化log文件的路径名称后，后续就要打开log文件，进行必要的初始化操作
                if (plen) {
                    name = malloc(plen + nlen + 2);
                    if (name == NULL) {
                        return NULL;
                    }

                    p = ngx_cpymem(name, prefix, plen);

                    if (!ngx_path_separator(*(p - 1))) {
                        *p++ = '/';
                    }

                    ngx_cpystrn(p, (u_char *) NGX_ERROR_LOG_PATH, nlen + 1);

                    p = name;
                }
            }

            ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
                        NGX_FILE_CREATE_OR_OPEN,
                        NGX_FILE_DEFAULT_ACCESS);
            /*
             *#define ngx_open_file(name, mode, create, access)                            \
             *open((const char *) name, mode|create, access)
             */
            //可以看到文件是以只写方式打开的，并执行追加的方式，如果文件不存在，则先创建该文件，并赋予文件0644的权限，创建者和超级用户才具有读写权限，其他用户和组用户只有读权限。这里要特别注意这一点，普通用户是没办法改写nginx的日志的，另外文件是初始化时候打开的初始化的，不要试图在运行过程中以超级用户权限删除文件，认为还会继续有日志文件产生记录。这个和apache是类似的
            if (ngx_log_file.fd == NGX_INVALID_FILE) {
                ngx_log_stderr(ngx_errno,
                            "[alert] could not open error log file: "
                            ngx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
                ngx_event_log(ngx_errno,
                            "could not open error log file: "
                            ngx_open_file_n " \"%s\" failed", name);
#endif

                ngx_log_file.fd = ngx_stderr;//如果文件创建出错，将标准错误赋给log文件描述符
            }

            if (p) {
                ngx_free(p);
            }
            //之前处理文件名这一串，都是为了打开文件做准备的，完毕后，它的使命也结束了，释放存储的内存。并返回，nginx的log便初始化完毕.
            return &ngx_log;
        }
    /* STUB */
#if (NGX_OPENSSL)
    ngx_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * ngx_process_options()
     */


    //#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log); //清零全局变量ngx_cycle，并为ngx_cycle.pool创建大小为1024B的内存池
    if (init_cycle.pool == NULL) {
        return 1;
    }

    ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log)
    {
        ngx_pool_t  *p;

        //分配一块size大小的内存
        p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
        if (p == NULL) {
            return NULL;
        }

        //对pool中的数据项赋初值
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.end = (u_char *) p + size;
        p->d.next = NULL;
        p->d.failed = 0;

        size = size - sizeof(ngx_pool_t);
        p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

        //继续赋初始值
        p->current = p;
        p->chain = NULL;
        p->large = NULL;
        p->cleanup = NULL;
        p->log = log;

        return p;
    }
    if (ngx_save_argv(&init_cycle, argc, argv) != NGX_OK) { //保存命令行参数至全局变量ngx_os_argv、ngx_argc、ngx_argv中
        return 1;
    }

    static ngx_int_t ngx_save_argv(ngx_cycle_t *cycle, int argc, char *const *argv)
    {
#if (NGX_FREEBSD)

        ngx_os_argv = (char **) argv;
        ngx_argc = argc;
        ngx_argv = (char **) argv;

#else
        size_t     len;
        ngx_int_t  i;

        ngx_os_argv = (char **) argv;
        ngx_argc = argc;

        ngx_argv = ngx_alloc((argc + 1) * sizeof(char *), cycle->log);
        if (ngx_argv == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < argc; i++) {
            len = ngx_strlen(argv[i]) + 1;

            ngx_argv[i] = ngx_alloc(len, cycle->log);
            if (ngx_argv[i] == NULL) {
                return NGX_ERROR;
            }

            (void) ngx_cpystrn((u_char *) ngx_argv[i], (u_char *) argv[i], len);
        }

        ngx_argv[i] = NULL;

#endif

        ngx_os_environ = environ;

        return NGX_OK;
    }
    if (ngx_process_options(&init_cycle) != NGX_OK) {//初始化ngx_cycle的prefix, conf_prefix, conf_file, conf_param等字段
        return 1;
    }

    static ngx_int_t ngx_process_options(ngx_cycle_t *cycle)
    {
        u_char  *p;
        size_t   len;

        if (ngx_prefix) {
            len = ngx_strlen(ngx_prefix);
            p = ngx_prefix;

            if (len && !ngx_path_separator(p[len - 1])) {
                p = ngx_pnalloc(cycle->pool, len + 1);
                if (p == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(p, ngx_prefix, len);
                p[len++] = '/';
            }

            cycle->conf_prefix.len = len;
            cycle->conf_prefix.data = p;
            cycle->prefix.len = len;
            cycle->prefix.data = p;

        } else {

#ifndef NGX_PREFIX

            p = ngx_pnalloc(cycle->pool, NGX_MAX_PATH);
            if (p == NULL) {
                return NGX_ERROR;
            }

            if (ngx_getcwd(p, NGX_MAX_PATH) == 0) {
                ngx_log_stderr(ngx_errno, "[emerg]: " ngx_getcwd_n " failed");
                return NGX_ERROR;
            }

            len = ngx_strlen(p);

            p[len++] = '/';

            cycle->conf_prefix.len = len;
            cycle->conf_prefix.data = p;
            cycle->prefix.len = len;
            cycle->prefix.data = p;

#else

#ifdef NGX_CONF_PREFIX
            ngx_str_set(&cycle->conf_prefix, NGX_CONF_PREFIX);
#else
            ngx_str_set(&cycle->conf_prefix, NGX_PREFIX);
#endif
            ngx_str_set(&cycle->prefix, NGX_PREFIX);

#endif
        }

        if (ngx_conf_file) {
            cycle->conf_file.len = ngx_strlen(ngx_conf_file);
            cycle->conf_file.data = ngx_conf_file;

        } else {
            ngx_str_set(&cycle->conf_file, NGX_CONF_PATH);
        }

        if (ngx_conf_full_name(cycle, &cycle->conf_file, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
                    p > cycle->conf_file.data;
                    p--)
        {
            if (ngx_path_separator(*p)) {
                cycle->conf_prefix.len = p - ngx_cycle->conf_file.data + 1;
                cycle->conf_prefix.data = ngx_cycle->conf_file.data;
                break;
            }
        }

        if (ngx_conf_params) {
            cycle->conf_param.len = ngx_strlen(ngx_conf_params);
            cycle->conf_param.data = ngx_conf_params;
        }

        if (ngx_test_config) {
            cycle->log->log_level = NGX_LOG_INFO;
        }

        return NGX_OK;
    }
    if (ngx_os_init(log) != NGX_OK) {//初始化系统相关变量，如内存页面大小ngx_pagesize,ngx_cacheline_size,最大连接数ngx_max_sockets等
        return 1;
    }

    ngx_int_t ngx_os_init(ngx_log_t *log)
    {
        ngx_uint_t  n;

#if (NGX_HAVE_OS_SPECIFIC_INIT)
        if (ngx_os_specific_init(log) != NGX_OK) {//OS特定的初始化
            return NGX_ERROR;
        }
#endif

        if (ngx_init_setproctitle(log) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_pagesize = getpagesize();           //nginx pagesize的设置
        ngx_cacheline_size = NGX_CPU_CACHE_LINE;//nginx缓存行尺寸的设置

        for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

#if (NGX_HAVE_SC_NPROCESSORS_ONLN)
        if (ngx_ncpu == 0) {
            ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        }
#endif

        if (ngx_ncpu < 1) {
            ngx_ncpu = 1;
        }

        ngx_cpuinfo();//该函数实际上也是设置 ngx_cacheline_size的值

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {//获取资源限制数据， 为后面的ngx_max_sockets做初始化
            ngx_log_error(NGX_LOG_ALERT, log, errno,
                        "getrlimit(RLIMIT_NOFILE) failed)");
            return NGX_ERROR;
        }

        ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;

#if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
        ngx_inherited_nonblocking = 1;
#else
        ngx_inherited_nonblocking = 0;
#endif

        srandom(ngx_time());//设置random函数的种子

        return NGX_OK;
    }

    /*
     * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
     */

    if (ngx_crc32_table_init() != NGX_OK) {//初始化一个做循环冗余校验的表，由此可以看出后续的循环冗余校验将采用高效的查表法
        return 1;
    }

    ngx_int_t ngx_crc32_table_init(void)
    {
        void  *p;

        if (((uintptr_t) ngx_crc32_table_short
                        & ~((uintptr_t) ngx_cacheline_size - 1))
                    == (uintptr_t) ngx_crc32_table_short)
        {
            return NGX_OK;
        }

        p = ngx_alloc(16 * sizeof(uint32_t) + ngx_cacheline_size, ngx_cycle->log);
        if (p == NULL) {
            return NGX_ERROR;
        }

        p = ngx_align_ptr(p, ngx_cacheline_size);

        ngx_memcpy(p, ngx_crc32_table16, 16 * sizeof(uint32_t));

        ngx_crc32_table_short = p;

        return NGX_OK;
    }
    if (ngx_add_inherited_sockets(&init_cycle) != NGX_OK) {//通过环境变量NGINX完成socket的继承，继承来的socket将会放到init_cycle的listening数组中。在NGINX环境变量中，每个socket中间用冒号或分号隔开。完成继承同时设置全局变量ngx_inherited为1
        return 1;
    }

    static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle)
    {
        u_char           *p, *v, *inherited;
        ngx_int_t         s;
        ngx_listening_t  *ls;

        //#define NGINX_VAR          "NGINX"
        inherited = (u_char *) getenv(NGINX_VAR);//获取NGINX环境变量

        if (inherited == NULL) {//如果没有NGINX这个环境变量， 直接返回OK
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                    "using inherited sockets from \"%s\"", inherited); //有的话， 记录一个NOTICE日志， 说明下使用的是继承的套接字

        if (ngx_array_init(&cycle->listening, cycle->pool, 10,
                        sizeof(ngx_listening_t))
                    != NGX_OK)
        {   //在内存池中初始化监听列表数组
            return NGX_ERROR;
        }

        //注意事项: 由于使用ngx_palloc分配内存，数组在扩容时，旧的内存不会被释放，会造成内存的浪费。因此，最好能提前规划好数组的容量，
        //在创建或者初始化的时候一次搞定，避免多次扩容，造成内存浪费。
        static ngx_inline ngx_int_t ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
        {
            /*
             * set "array->nelts" before "array->elts", otherwise MSVC thinks
             * that "array->nelts" may be used without having been initialized
             */

            array->nelts = 0;
            array->size = size;
            array->nalloc = n;
            array->pool = pool;

            array->elts = ngx_palloc(pool, n * size);
            if (array->elts == NULL) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        for (p = inherited, v = p; *p; p++) {
            if (*p == ':' || *p == ';') {
                s = ngx_atoi(v, p - v);
                if (s == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                                "invalid socket number \"%s\" in " NGINX_VAR
                                " environment variable, ignoring the rest"
                                " of the variable", v);
                    break;
                }

                v = p + 1;

                //将继承的塞入到监听队列中
                ls = ngx_array_push(&cycle->listening);
                if (ls == NULL) {
                    return NGX_ERROR;
                }

                ngx_memzero(ls, sizeof(ngx_listening_t));

                ls->fd = (ngx_socket_t) s;
            }
        }

        ngx_inherited = 1;

        return ngx_set_inherited_sockets(cycle);//初始化监听数组的数据
        ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle)
        {
            size_t                     len;
            ngx_uint_t                 i;
            ngx_listening_t           *ls;
            socklen_t                  olen;
#if (NGX_HAVE_DEFERRED_ACCEPT || NGX_HAVE_TCP_FASTOPEN)
            ngx_err_t                  err;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            struct accept_filter_arg   af;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            int                        timeout;
#endif

            ls = cycle->listening.elts;
            for (i = 0; i < cycle->listening.nelts; i++) {

                ls[i].sockaddr = ngx_palloc(cycle->pool, NGX_SOCKADDRLEN);
                if (ls[i].sockaddr == NULL) {
                    return NGX_ERROR;
                }

                ls[i].socklen = NGX_SOCKADDRLEN;
                if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
                    ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                                "getsockname() of the inherited "
                                "socket #%d failed", ls[i].fd);
                    ls[i].ignore = 1;
                    continue;
                }

                switch (ls[i].sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
                    case AF_INET6:
                        ls[i].addr_text_max_len = NGX_INET6_ADDRSTRLEN;
                        len = NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;
                        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
                    case AF_UNIX:
                        ls[i].addr_text_max_len = NGX_UNIX_ADDRSTRLEN;
                        len = NGX_UNIX_ADDRSTRLEN;
                        break;
#endif

                    case AF_INET:
                        ls[i].addr_text_max_len = NGX_INET_ADDRSTRLEN;
                        len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
                        break;

                    default:
                        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                                    "the inherited socket #%d has "
                                    "an unsupported protocol family", ls[i].fd);
                        ls[i].ignore = 1;
                        continue;
                }

                ls[i].addr_text.data = ngx_pnalloc(cycle->pool, len);
                if (ls[i].addr_text.data == NULL) {
                    return NGX_ERROR;
                }

                len = ngx_sock_ntop(ls[i].sockaddr, ls[i].socklen,
                            ls[i].addr_text.data, len, 1);
                if (len == 0) {
                    return NGX_ERROR;
                }

                ls[i].addr_text.len = len;

                ls[i].backlog = NGX_LISTEN_BACKLOG;

                olen = sizeof(int);

                if (getsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF, (void *) &ls[i].rcvbuf,
                                &olen)
                            == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                                "getsockopt(SO_RCVBUF) %V failed, ignored",
                                &ls[i].addr_text);

                    ls[i].rcvbuf = -1;
                }

                olen = sizeof(int);

                if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF, (void *) &ls[i].sndbuf,
                                &olen)
                            == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                                "getsockopt(SO_SNDBUF) %V failed, ignored",
                                &ls[i].addr_text);

                    ls[i].sndbuf = -1;
                }

#if 0
                /* SO_SETFIB is currently a set only option */

#if (NGX_HAVE_SETFIB)

                olen = sizeof(int);

                if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                                (void *) &ls[i].setfib, &olen)
                            == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                                "getsockopt(SO_SETFIB) %V failed, ignored",
                                &ls[i].addr_text);

                    ls[i].setfib = -1;
                }

#endif
#endif

#if (NGX_HAVE_TCP_FASTOPEN)

                olen = sizeof(int);

                if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                                (void *) &ls[i].fastopen, &olen)
                            == -1)
                {
                    err = ngx_socket_errno;

                    if (err != NGX_EOPNOTSUPP && err != NGX_ENOPROTOOPT) {
                        ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
                                    "getsockopt(TCP_FASTOPEN) %V failed, ignored",
                                    &ls[i].addr_text);
                    }

                    ls[i].fastopen = -1;
                }

#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                ngx_memzero(&af, sizeof(struct accept_filter_arg));
                olen = sizeof(struct accept_filter_arg);

                if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &olen)
                            == -1)
                {
                    err = ngx_socket_errno;

                    if (err == NGX_EINVAL) {
                        continue;
                    }

                    ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
                                "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
                                &ls[i].addr_text);
                    continue;
                }

                if (olen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
                    continue;
                }

                ls[i].accept_filter = ngx_palloc(cycle->pool, 16);
                if (ls[i].accept_filter == NULL) {
                    return NGX_ERROR;
                }

                (void) ngx_cpystrn((u_char *) ls[i].accept_filter,
                            (u_char *) af.af_name, 16);
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                timeout = 0;
                olen = sizeof(int);

                if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &olen)
                            == -1)
                {
                    err = ngx_socket_errno;

                    if (err == NGX_EOPNOTSUPP) {
                        continue;
                    }

                    ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
                                "getsockopt(TCP_DEFER_ACCEPT) for %V failed, ignored",
                                &ls[i].addr_text);
                    continue;
                }

                if (olen < sizeof(int) || timeout == 0) {
                    continue;
                }

                ls[i].deferred_accept = 1;
#endif
            }

            return NGX_OK;
        }
    }
    //对所有模块进行计数
    ngx_max_module = 0;//记录模块数，每个模块用唯一的index区别
    //初始化每个module的index，并计算ngx_max_module
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    cycle = ngx_init_cycle(&init_cycle);//nginx启动比较核心的一部分功能， 很多的变量都在这个过程进行初始化
    if (cycle == NULL) {
        if (ngx_test_config) {
            ngx_log_stderr(0, "configuration file %s test failed",
                        init_cycle.conf_file.data);
        }

        return 1;
    }

    ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle)
    {
        void                *rv;
        char               **senv, **env;
        ngx_uint_t           i, n;
        ngx_log_t           *log;
        ngx_time_t          *tp;
        ngx_conf_t           conf;
        ngx_pool_t          *pool;
        ngx_cycle_t         *cycle, **old;
        ngx_shm_zone_t      *shm_zone, *oshm_zone;
        ngx_list_part_t     *part, *opart;
        ngx_open_file_t     *file;
        ngx_listening_t     *ls, *nls;
        ngx_core_conf_t     *ccf, *old_ccf;
        ngx_core_module_t   *module;
        char                 hostname[NGX_MAXHOSTNAMELEN];

        ngx_timezone_update();//更新时区

        void ngx_timezone_update(void)
        {
#if (NGX_FREEBSD)

            if (getenv("TZ")) {
                return;
            }

            putenv("TZ=UTC");

            tzset();

            unsetenv("TZ");

            tzset();

#elif (NGX_LINUX)
            time_t      s;
            struct tm  *t;
            char        buf[4];

            s = time(0);

            t = localtime(&s);

            strftime(buf, 4, "%H", t);

#endif
        }
        /* force localtime update with a new timezone */

        tp = ngx_timeofday();
        tp->sec = 0;

        ngx_time_update();//更新时间

        void ngx_time_update(void)
        {
            u_char          *p0, *p1, *p2, *p3, *p4;
            ngx_tm_t         tm, gmt;
            time_t           sec;
            ngx_uint_t       msec;
            ngx_time_t      *tp;
            struct timeval   tv;

            if (!ngx_trylock(&ngx_time_lock)) {
                return;
            }

            ngx_gettimeofday(&tv);

            sec = tv.tv_sec;
            msec = tv.tv_usec / 1000;

            ngx_current_msec = (ngx_msec_t) sec * 1000 + msec;

            tp = &cached_time[slot];

            if (tp->sec == sec) {
                tp->msec = msec;
                ngx_unlock(&ngx_time_lock);
                return;
            }

            if (slot == NGX_TIME_SLOTS - 1) {
                slot = 0;
            } else {
                slot++;
            }

            tp = &cached_time[slot];

            tp->sec = sec;
            tp->msec = msec;

            ngx_gmtime(sec, &gmt);


            p0 = &cached_http_time[slot][0];

            (void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                        week[gmt.ngx_tm_wday], gmt.ngx_tm_mday,
                        months[gmt.ngx_tm_mon - 1], gmt.ngx_tm_year,
                        gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec);

#if (NGX_HAVE_GETTIMEZONE)

            tp->gmtoff = ngx_gettimezone();
            ngx_gmtime(sec + tp->gmtoff * 60, &tm);

#elif (NGX_HAVE_GMTOFF)

            ngx_localtime(sec, &tm);
            cached_gmtoff = (ngx_int_t) (tm.ngx_tm_gmtoff / 60);
            tp->gmtoff = cached_gmtoff;

#else

            ngx_localtime(sec, &tm);
            cached_gmtoff = ngx_timezone(tm.ngx_tm_isdst);
            tp->gmtoff = cached_gmtoff;

#endif


            p1 = &cached_err_log_time[slot][0];

            (void) ngx_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
                        tm.ngx_tm_year, tm.ngx_tm_mon,
                        tm.ngx_tm_mday, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec);


            p2 = &cached_http_log_time[slot][0];

            (void) ngx_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
                        tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                        tm.ngx_tm_year, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec,
                        tp->gmtoff < 0 ? '-' : '+',
                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

            p3 = &cached_http_log_iso8601[slot][0];

            (void) ngx_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d",
                        tm.ngx_tm_year, tm.ngx_tm_mon,
                        tm.ngx_tm_mday, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec,
                        tp->gmtoff < 0 ? '-' : '+',
                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

            p4 = &cached_syslog_time[slot][0];

            (void) ngx_sprintf(p4, "%s %2d %02d:%02d:%02d",
                        months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
                        tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

            ngx_memory_barrier();

            ngx_cached_time = tp;
            ngx_cached_http_time.data = p0;
            ngx_cached_err_log_time.data = p1;
            ngx_cached_http_log_time.data = p2;
            ngx_cached_http_log_iso8601.data = p3;
            ngx_cached_syslog_time.data = p4;

            ngx_unlock(&ngx_time_lock);
        }

        log = old_cycle->log;

        //创建大小为NGX_CYCLE_POOL_SIZE=16KB的内存池
        pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
        if (pool == NULL) {
            return NULL;
        }
        pool->log = log;

        //分配ngx_cycle_t结构
        cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
        if (cycle == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        //简单初始化，如记录pool指针、log指针
        cycle->pool = pool;
        cycle->log = log;
        cycle->old_cycle = old_cycle;

        //初始化配置前缀、前缀、配置文件、配置参数等字符串
        cycle->conf_prefix.len = old_cycle->conf_prefix.len;
        cycle->conf_prefix.data = ngx_pstrdup(pool, &old_cycle->conf_prefix);
        if (cycle->conf_prefix.data == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        cycle->prefix.len = old_cycle->prefix.len;
        cycle->prefix.data = ngx_pstrdup(pool, &old_cycle->prefix);
        if (cycle->prefix.data == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        cycle->conf_file.len = old_cycle->conf_file.len;
        cycle->conf_file.data = ngx_pnalloc(pool, old_cycle->conf_file.len + 1);
        if (cycle->conf_file.data == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }
        ngx_cpystrn(cycle->conf_file.data, old_cycle->conf_file.data,
                    old_cycle->conf_file.len + 1);

        cycle->conf_param.len = old_cycle->conf_param.len;
        cycle->conf_param.data = ngx_pstrdup(pool, &old_cycle->conf_param);
        if (cycle->conf_param.data == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        //初始化pathes数组
        n = old_cycle->paths.nelts ? old_cycle->paths.nelts : 10;

        cycle->paths.elts = ngx_pcalloc(pool, n * sizeof(ngx_path_t *));
        if (cycle->paths.elts == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        cycle->paths.nelts = 0;
        cycle->paths.size = sizeof(ngx_path_t *);
        cycle->paths.nalloc = n;
        cycle->paths.pool = pool;


        if (old_cycle->open_files.part.nelts) {
            n = old_cycle->open_files.part.nelts;
            for (part = old_cycle->open_files.part.next; part; part = part->next) {
                n += part->nelts;
            }

        } else {
            n = 20;
        }

        //初始化open_files链表
        if (ngx_list_init(&cycle->open_files, pool, n, sizeof(ngx_open_file_t))
                    != NGX_OK)
        {
            ngx_destroy_pool(pool);
            return NULL;
        }

        //初始化shared_memory链表
        if (old_cycle->shared_memory.part.nelts) {
            n = old_cycle->shared_memory.part.nelts;
            for (part = old_cycle->shared_memory.part.next; part; part = part->next)
            {
                n += part->nelts;
            }

        } else {
            n = 1;
        }

        if (ngx_list_init(&cycle->shared_memory, pool, n, sizeof(ngx_shm_zone_t))
                    != NGX_OK)
        {
            ngx_destroy_pool(pool);
            return NULL;
        }

        //初始化listening数组
        n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;

        cycle->listening.elts = ngx_pcalloc(pool, n * sizeof(ngx_listening_t));
        if (cycle->listening.elts == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        cycle->listening.nelts = 0;
        cycle->listening.size = sizeof(ngx_listening_t);
        cycle->listening.nalloc = n;
        cycle->listening.pool = pool;

        //初始化resuable_connections_queue队列
        ngx_queue_init(&cycle->reusable_connections_queue);


        //从pool为conf_ctx分配空间
        cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
        if (cycle->conf_ctx == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }


        //初始化hostname字符串
        if (gethostname(hostname, NGX_MAXHOSTNAMELEN) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "gethostname() failed");
            ngx_destroy_pool(pool);
            return NULL;
        }

        /* on Linux gethostname() silently truncates name that does not fit */

        hostname[NGX_MAXHOSTNAMELEN - 1] = '\0';
        cycle->hostname.len = ngx_strlen(hostname);

        cycle->hostname.data = ngx_pnalloc(pool, cycle->hostname.len);
        if (cycle->hostname.data == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        ngx_strlow(cycle->hostname.data, (u_char *) hostname, cycle->hostname.len);


        //调用core模块的create_conf()
        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->type != NGX_CORE_MODULE) {
                continue;
            }

            module = ngx_modules[i]->ctx;

            if (module->create_conf) {
                rv = module->create_conf(cycle);
                if (rv == NULL) {
                    ngx_destroy_pool(pool);
                    return NULL;
                }
                cycle->conf_ctx[ngx_modules[i]->index] = rv;
            }
        }


        senv = environ;


        ngx_memzero(&conf, sizeof(ngx_conf_t));
        /* STUB: init array ? */
        conf.args = ngx_array_create(pool, 10, sizeof(ngx_str_t));
        if (conf.args == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        conf.temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
        if (conf.temp_pool == NULL) {
            ngx_destroy_pool(pool);
            return NULL;
        }


        conf.ctx = cycle->conf_ctx;
        conf.cycle = cycle;
        conf.pool = pool;
        conf.log = log;
        conf.module_type = NGX_CORE_MODULE;
        conf.cmd_type = NGX_MAIN_CONF;

#if 0
        log->log_level = NGX_LOG_DEBUG_ALL;
#endif

        //配置文件解析
        if (ngx_conf_param(&conf) != NGX_CONF_OK) {
            environ = senv;
            ngx_destroy_cycle_pools(&conf);
            return NULL;
        }

        if (ngx_conf_parse(&conf, &cycle->conf_file) != NGX_CONF_OK) {
            environ = senv;
            ngx_destroy_cycle_pools(&conf);
            return NULL;
        }

        if (ngx_test_config && !ngx_quiet_mode) {
            ngx_log_stderr(0, "the configuration file %s syntax is ok",
                        cycle->conf_file.data);
        }

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->type != NGX_CORE_MODULE) {
                continue;
            }

            module = ngx_modules[i]->ctx;

            //调用core模块的init_conf()
            if (module->init_conf) {
                if (module->init_conf(cycle, cycle->conf_ctx[ngx_modules[i]->index])
                            == NGX_CONF_ERROR)
                {
                    environ = senv;
                    ngx_destroy_cycle_pools(&conf);
                    return NULL;
                }
            }
        }

        if (ngx_process == NGX_PROCESS_SIGNALLER) {
            return cycle;
        }

        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

        if (ngx_test_config) {

            if (ngx_create_pidfile(&ccf->pid, log) != NGX_OK) {
                goto failed;
            }

        } else if (!ngx_is_init_cycle(old_cycle)) {

            /*
             * we do not create the pid file in the first ngx_init_cycle() call
             * because we need to write the demonized process pid
             */

            old_ccf = (ngx_core_conf_t *) ngx_get_conf(old_cycle->conf_ctx,
                        ngx_core_module);
            if (ccf->pid.len != old_ccf->pid.len
                        || ngx_strcmp(ccf->pid.data, old_ccf->pid.data) != 0)
            {
                /* new pid file name */

                if (ngx_create_pidfile(&ccf->pid, log) != NGX_OK) {
                    goto failed;
                }

                ngx_delete_pidfile(old_cycle);
            }
        }


        if (ngx_test_lockfile(cycle->lock_file.data, log) != NGX_OK) {
            goto failed;
        }


        if (ngx_create_paths(cycle, ccf->user) != NGX_OK) {
            goto failed;
        }


        if (ngx_log_open_default(cycle) != NGX_OK) {
            goto failed;
        }

        /* open the new files */
        //遍历open_files链表中的每一个文件并打开
        part = &cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (file[i].name.len == 0) {
                continue;
            }

            file[i].fd = ngx_open_file(file[i].name.data,
                        NGX_FILE_APPEND,
                        NGX_FILE_CREATE_OR_OPEN,
                        NGX_FILE_DEFAULT_ACCESS);

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, log, 0,
                        "log: %p %d \"%s\"",
                        &file[i], file[i].fd, file[i].name.data);

            if (file[i].fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                            ngx_open_file_n " \"%s\" failed",
                            file[i].name.data);
                goto failed;
            }

#if !(NGX_WIN32)
            if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                            "fcntl(FD_CLOEXEC) \"%s\" failed",
                            file[i].name.data);
                goto failed;
            }
#endif
        }

        cycle->log = &cycle->new_log;
        pool->log = &cycle->new_log;


        /* create shared memory */
        //创建共享内存并初始化(新旧shared_memory链表的比较，相同的共享内存保留，旧的不同的共享内存被释放，新的被创建)
        part = &cycle->shared_memory.part;
        shm_zone = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                shm_zone = part->elts;
                i = 0;
            }

            if (shm_zone[i].shm.size == 0) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                            "zero size shared memory zone \"%V\"",
                            &shm_zone[i].shm.name);
                goto failed;
            }

            shm_zone[i].shm.log = cycle->log;

            opart = &old_cycle->shared_memory.part;
            oshm_zone = opart->elts;

            for (n = 0; /* void */ ; n++) {

                if (n >= opart->nelts) {
                    if (opart->next == NULL) {
                        break;
                    }
                    opart = opart->next;
                    oshm_zone = opart->elts;
                    n = 0;
                }

                if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                    continue;
                }

                if (ngx_strncmp(shm_zone[i].shm.name.data,
                                oshm_zone[n].shm.name.data,
                                shm_zone[i].shm.name.len)
                            != 0)
                {
                    continue;
                }

                if (shm_zone[i].tag == oshm_zone[n].tag
                            && shm_zone[i].shm.size == oshm_zone[n].shm.size)
                {
                    shm_zone[i].shm.addr = oshm_zone[n].shm.addr;

                    if (shm_zone[i].init(&shm_zone[i], oshm_zone[n].data)
                                != NGX_OK)
                    {
                        goto failed;
                    }

                    goto shm_zone_found;
                }

                ngx_shm_free(&oshm_zone[n].shm);

                break;
            }

            if (ngx_shm_alloc(&shm_zone[i].shm) != NGX_OK) {
                goto failed;
            }

            if (ngx_init_zone_pool(cycle, &shm_zone[i]) != NGX_OK) {
                goto failed;
            }

            if (shm_zone[i].init(&shm_zone[i], NULL) != NGX_OK) {
                goto failed;
            }

shm_zone_found:

            continue;
        }


        /* handle the listening sockets */
        //(尝试5遍)遍历listening数组并打开所有侦听sockets(socket()->setsockopt()->bind()->listen())
        if (old_cycle->listening.nelts) {
            ls = old_cycle->listening.elts;
            for (i = 0; i < old_cycle->listening.nelts; i++) {
                ls[i].remain = 0;
            }

            nls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {

                for (i = 0; i < old_cycle->listening.nelts; i++) {
                    if (ls[i].ignore) {
                        continue;
                    }

                    if (ngx_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
                                    ls[i].sockaddr, ls[i].socklen, 1)
                                == NGX_OK)
                    {
                        nls[n].fd = ls[i].fd;
                        nls[n].previous = &ls[i];
                        ls[i].remain = 1;

                        if (ls[i].backlog != nls[n].backlog) {
                            nls[n].listen = 1;
                        }

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                        /*
                         * FreeBSD, except the most recent versions,
                         * could not remove accept filter
                         */
                        nls[n].deferred_accept = ls[i].deferred_accept;

                        if (ls[i].accept_filter && nls[n].accept_filter) {
                            if (ngx_strcmp(ls[i].accept_filter,
                                            nls[n].accept_filter)
                                        != 0)
                            {
                                nls[n].delete_deferred = 1;
                                nls[n].add_deferred = 1;
                            }

                        } else if (ls[i].accept_filter) {
                            nls[n].delete_deferred = 1;

                        } else if (nls[n].accept_filter) {
                            nls[n].add_deferred = 1;
                        }
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                        if (ls[i].deferred_accept && !nls[n].deferred_accept) {
                            nls[n].delete_deferred = 1;

                        } else if (ls[i].deferred_accept != nls[n].deferred_accept)
                        {
                            nls[n].add_deferred = 1;
                        }
#endif
                        break;
                    }
                }

                if (nls[n].fd == (ngx_socket_t) -1) {
                    nls[n].open = 1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                    if (nls[n].accept_filter) {
                        nls[n].add_deferred = 1;
                    }
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
                    if (nls[n].deferred_accept) {
                        nls[n].add_deferred = 1;
                    }
#endif
                }
            }

        } else {
            ls = cycle->listening.elts;
            for (i = 0; i < cycle->listening.nelts; i++) {
                ls[i].open = 1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                if (ls[i].accept_filter) {
                    ls[i].add_deferred = 1;
                }
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
                if (ls[i].deferred_accept) {
                    ls[i].add_deferred = 1;
                }
#endif
            }
        }

        if (ngx_open_listening_sockets(cycle) != NGX_OK) {
            goto failed;
        }

        if (!ngx_test_config) {
            ngx_configure_listening_sockets(cycle);
        }


        /* commit the new cycle configuration */
        //提交新的cycle配置，并调用所有模块的init_module(实际上只有ngx_event_core_module模块定义了该callback，即只有ngx_event_module_init()被调用)
        if (!ngx_use_stderr) {
            (void) ngx_log_redirect_stderr(cycle);
        }

        pool->log = cycle->log;

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->init_module) {
                if (ngx_modules[i]->init_module(cycle) != NGX_OK) {
                    /* fatal */
                    exit(1);
                }
            }
        }


        /* close and delete stuff that lefts from an old cycle */

        /* free the unnecessary shared memory */
        //关闭或删除残留在old_cycle中的资源
        //释放多余的共享内存
        opart = &old_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= opart->nelts) {
                if (opart->next == NULL) {
                    goto old_shm_zone_done;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                i = 0;
            }

            part = &cycle->shared_memory.part;
            shm_zone = part->elts;

            for (n = 0; /* void */ ; n++) {

                if (n >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }
                    part = part->next;
                    shm_zone = part->elts;
                    n = 0;
                }

                if (oshm_zone[i].shm.name.len == shm_zone[n].shm.name.len
                            && ngx_strncmp(oshm_zone[i].shm.name.data,
                                shm_zone[n].shm.name.data,
                                oshm_zone[i].shm.name.len)
                            == 0)
                {
                    goto live_shm_zone;
                }
            }

            ngx_shm_free(&oshm_zone[i].shm);

live_shm_zone:

            continue;
        }

old_shm_zone_done:


        /* close the unnecessary listening sockets */
        //关闭多余的侦听sockets

        ls = old_cycle->listening.elts;
        for (i = 0; i < old_cycle->listening.nelts; i++) {

            if (ls[i].remain || ls[i].fd == (ngx_socket_t) -1) {
                continue;
            }

            if (ngx_close_socket(ls[i].fd) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                            ngx_close_socket_n " listening socket on %V failed",
                            &ls[i].addr_text);
            }

#if (NGX_HAVE_UNIX_DOMAIN)

            if (ls[i].sockaddr->sa_family == AF_UNIX) {
                u_char  *name;

                name = ls[i].addr_text.data + sizeof("unix:") - 1;

                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                            "deleting socket %s", name);

                if (ngx_delete_file(name) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                ngx_delete_file_n " %s failed", name);
                }
            }

#endif
        }


        /* close the unnecessary open files */
        //关闭多余的打开文件

        part = &old_cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
                continue;
            }

            if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                            ngx_close_file_n " \"%s\" failed",
                            file[i].name.data);
            }
        }

        ngx_destroy_pool(conf.temp_pool);

        if (ngx_process == NGX_PROCESS_MASTER || ngx_is_init_cycle(old_cycle)) {

            /*
             * perl_destruct() frees environ, if it is not the same as it was at
             * perl_construct() time, therefore we save the previous cycle
             * environment before ngx_conf_parse() where it will be changed.
             */

            env = environ;
            environ = senv;

            ngx_destroy_pool(old_cycle->pool);
            cycle->old_cycle = NULL;

            environ = env;

            return cycle;
        }


        if (ngx_temp_pool == NULL) {
            ngx_temp_pool = ngx_create_pool(128, cycle->log);
            if (ngx_temp_pool == NULL) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                            "could not create ngx_temp_pool");
                exit(1);
            }

            n = 10;
            ngx_old_cycles.elts = ngx_pcalloc(ngx_temp_pool,
                        n * sizeof(ngx_cycle_t *));
            if (ngx_old_cycles.elts == NULL) {
                exit(1);
            }
            ngx_old_cycles.nelts = 0;
            ngx_old_cycles.size = sizeof(ngx_cycle_t *);
            ngx_old_cycles.nalloc = n;
            ngx_old_cycles.pool = ngx_temp_pool;

            ngx_cleaner_event.handler = ngx_clean_old_cycles;
            ngx_cleaner_event.log = cycle->log;
            ngx_cleaner_event.data = &dumb;
            dumb.fd = (ngx_socket_t) -1;
        }

        ngx_temp_pool->log = cycle->log;

        old = ngx_array_push(&ngx_old_cycles);
        if (old == NULL) {
            exit(1);
        }
        *old = old_cycle;

        if (!ngx_cleaner_event.timer_set) {
            ngx_add_timer(&ngx_cleaner_event, 30000);
            ngx_cleaner_event.timer_set = 1;
        }

        return cycle;


failed:   //容错

        if (!ngx_is_init_cycle(old_cycle)) {
            old_ccf = (ngx_core_conf_t *) ngx_get_conf(old_cycle->conf_ctx,
                        ngx_core_module);
            if (old_ccf->environment) {
                environ = old_ccf->environment;
            }
        }

        /* rollback the new cycle configuration */

        part = &cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
                continue;
            }

            if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                            ngx_close_file_n " \"%s\" failed",
                            file[i].name.data);
            }
        }

        if (ngx_test_config) {
            ngx_destroy_cycle_pools(&conf);
            return NULL;
        }

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].fd == (ngx_socket_t) -1 || !ls[i].open) {
                continue;
            }

            if (ngx_close_socket(ls[i].fd) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                            ngx_close_socket_n " %V failed",
                            &ls[i].addr_text);
            }
        }

        ngx_destroy_cycle_pools(&conf);

        return NULL;
    }

    if (ngx_test_config) {
        if (!ngx_quiet_mode) {
            ngx_log_stderr(0, "configuration file %s test is successful",
                        cycle->conf_file.data);
        }

        return 0;
    }

    //若有信号，则进入ngx_signal_process()处理
    if (ngx_signal) {//热加载，再不关闭服务同时加载新配置信息
        return ngx_signal_process(cycle, ngx_signal);
    }
    //nginx有个pid文件，里面记录了，当前正在运行的nginxmaster进程的pid，所以程序会通过这个文件得到进程的pid，和信号字符串对应的signo，最后使用kill来完成信号的发送

    ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig)
    {
        ssize_t           n;
        ngx_int_t         pid;
        ngx_file_t        file;
        ngx_core_conf_t  *ccf;
        u_char            buf[NGX_INT64_LEN + 2];

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "signal process started");

        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

        ngx_memzero(&file, sizeof(ngx_file_t));

        file.name = ccf->pid;
        file.log = cycle->log;

        file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                    NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

        if (file.fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                        ngx_open_file_n " \"%s\" failed", file.name.data);
            return 1;
        }

        n = ngx_read_file(&file, buf, NGX_INT64_LEN + 2, 0);

        if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                        ngx_close_file_n " \"%s\" failed", file.name.data);
        }

        if (n == NGX_ERROR) {
            return 1;
        }

        while (n-- && (buf[n] == CR || buf[n] == LF)) { /* void */ }

        pid = ngx_atoi(buf, ++n);

        if (pid == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "invalid PID number \"%*s\" in \"%s\"",
                        n, buf, file.name.data);
            return 1;
        }

        return ngx_os_signal_process(cycle, sig, pid);

    }
    ngx_os_status(cycle->log);

    ngx_cycle = cycle;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->master && ngx_process == NGX_PROCESS_SINGLE) {
        ngx_process = NGX_PROCESS_MASTER;
    }

#if !(NGX_WIN32)
    //调用ngx_init_signals()初始化信号；主要完成信号处理程序的注册
    if (ngx_init_signals(cycle->log) != NGX_OK) {
        return 1;
    }

    ngx_int_t ngx_init_signals(ngx_log_t *log)
    {
        ngx_signal_t      *sig;
        struct sigaction   sa;
        
        //signals数组
        for (sig = signals; sig->signo != 0; sig++) {
            ngx_memzero(&sa, sizeof(struct sigaction));
            sa.sa_handler = sig->handler;
            sigemptyset(&sa.sa_mask);
            if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (NGX_VALGRIND)
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                            "sigaction(%s) failed, ignored", sig->signame);
#else
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                            "sigaction(%s) failed", sig->signame);
                return NGX_ERROR;
#endif
            }
        }

        return NGX_OK;
    }

    //若无继承sockets，且设置了守护进程标识，则调用ngx_daemon()创建守护进程
    //在daemon模式下，调用ngx_daemon以守护进程的方式运行。这里可以在./configure的时候加入参数—with-debug，并在nginx.conf中配置:
    //master_process  off; # 简化调试 此指令不得用于生产环境
    //daemon          off; # 简化调试 此指令可以用到生产环境
    //可以取消守护进程模式以及master线程模型。
    if (!ngx_inherited && ccf->daemon) {
        if (ngx_daemon(cycle->log) != NGX_OK) {
            return 1;
        }

        ngx_daemonized = 1;
    }

    if (ngx_inherited) {
        ngx_daemonized = 1;
    }

#endif

    //调用ngx_create_pidfile创建pid文件，把master进程的pid保存在里面
    //调用ngx_create_pidfile()创建进程记录文件；(非NGX_PROCESS_MASTER=1进程，不创建该文件)
    if (ngx_create_pidfile(&ccf->pid, cycle->log) != NGX_OK) {
        return 1;
    }

    if (ngx_log_redirect_stderr(cycle) != NGX_OK) {
        return 1;
    }

    if (log->file->fd != ngx_stderr) {
        if (ngx_close_file(log->file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                        ngx_close_file_n " built-in log failed");
        }
    }

    ngx_use_stderr = 0;

    //通过ngx_start_worker_processes开启新进程，而之前的进程则通过ngx_signal_worker_processes，来发送信号来“优雅”的关闭，所谓优雅的关闭，是指当前真正处理请求的进程会等到处理完之后再退出，同时当前的进程停止listen，不再accept新的请求了
    //若为NGX_PROCESS_SINGLE=1模式，则调用ngx_single_process_cycle()进入进程循环
    if (ngx_process == NGX_PROCESS_SINGLE) {
        ngx_single_process_cycle(cycle);//单进程模式

        //否则为master-worker模式，调用ngx_master_process_cycle()进入进程循环
    } else {
        ngx_master_process_cycle(cycle);//多进程模式
    }

    return 0;
}
