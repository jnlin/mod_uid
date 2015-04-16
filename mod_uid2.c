/* 
 * ====================================================================
 *          mod_uid   version 1.0
 * ====================================================================
 * Copyright (c) 2000-2002 Alex Tutubalin <lexa@lexa.ru> (http://www.lexa.ru/lexa/
 */

/*
  Конфигурационные директивы:
  UIDActive On/Off - включить-выключить выдачу куки
  UIDCookieName - имя cookie (default - uid)
  UIDService number - "номер сервиса" (см README, default - IP-адрес сервера )
  UIDDomain .domain.name - имя домена для которого выдается кука
			   (default - нет домена)
  UIDPath - путь для которого выдается cookie (default - /)
   Задание Expiration date для cookie (default - 10 лет)
  UIDExpires number  - прибавлять к текущей дате number секунд
   или
  UIDExpires plus 3 year 4 month 2 day 1 hour 15 minutes - то же
                          самое, но выраженное по человечески.
  UIDP3P On/Off/Always -управляет выдачей заголовка P3P одновременно 
                  с выдачей cookie (default - Off). 
		  Варианты:
                  Off - не выдавать заголовок P3P
                  On - выдавать только если у Cookie выдается параметр 
			domain
                  Always - выдавать всегда (т.е. даже без domain)
                  Заголовок P3P выдается только если выдается
		  заголовок Set-Cookie
  UIDP3PString - текст заголовка P3P (default -  CP="NOI PSA OUR BUS UNI")
  
   Формат куки:
   В двоичном виде:
   unsigned int cookie[4], где
   cookie[0] - номер сервиса
   cookie[1] - время выдачи (unix time)
   cookie[2] - pid процесса выдавшего куку
   cookie[3] - старшие 24 бита - уникальный секвенсер
               в пределах процесса, младшие 8 бит - номер версии куки (2).

   Клиенту отдается этот массив (128 бит) в кодировке base64 в network 
   order;
   В логах появляется в шестнадцатиричном виде (соответственно строка из 32 символов)

   Что появляется в логах.
   В LogFormat нужно написать
   %{uid_set}n - кука, отданная пользователю (если он не предъявил свою)
   %{uid_got}n - кука, полученная от пользователя.

Удобный Log-format может выглядеть как-то так:

LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{uid_got}n\" \"%{uid_set}n\" combined_cookie

Такой формат лога без проблем понимают и Analog и Webtrends (для
Webtrends сущестенно, что полученная cookie расположена сразу после User-Agent).

*/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#if !defined(WIN32) && !defined(MPE)
#include <sys/time.h>
#endif

module AP_MODULE_DECLARE_DATA uid2_module;

#define COOKIE_VERSION	2
#define DEF_NAME	"uid"
#define DEF_EXPIRES	315576000 /* 10 years */
#define DEF_DOMAIN	NULL
#define DEF_PATH	"/"
#define DEF_P3P		"CP=\"NOI PSA OUR BUS UNI\""
#define CBUFSIZE	50

#define SEQ_MIN		0x030303
#define SEQ_MAX		0xffffff


#define UID_SERVICE(lk)	lk[0]
#define UID_TIME(lk)	lk[1]
#define UID_PID(lk)	lk[2]
#define UID_SEQ_GET(lk)	(lk[3]>>8)
#define UID_VER_GET(lk)	(lk[3]&0xff)
#define UID_SEQ_VER_SET(lk,seq,ver) (lk[3]=(seq<<8)|(ver&0xff))


#define NOTSET		0
#define OFF		1
#define ON		2
#define ALWAYS		3

typedef struct 
{
    int enabled;
    char *cookie_name;
    char *domain;
    char *path;
    unsigned int service;
    time_t expires;
    int p3p_enabled;
    char *p3p_header;
} cookie_dir_rec;

#define OVER(field) (over->field?over->field:base->field)


static int sequencer;

static void print_cookie(char *cbuf, unsigned int *lk)
{
  sprintf(cbuf,"%08X%08X%08X%08X",lk[0],lk[1],lk[2],lk[3]);
}


static void make_cookie(request_rec *r, cookie_dir_rec *dcfg)
{
    unsigned int lk[4]; /* new cookie buf */
    char *cname;
    char *cdomain;
    char *cpath;
    unsigned int cdelta;
    unsigned int service;
    char* p3ph;
    int i;
    char *cookbuf,*new_cookie;
    char cbuf[CBUFSIZE];
    time_t when;
    struct tm *tms;
    int len;

    bzero(lk,sizeof(lk));
    // init
    cname = dcfg->cookie_name ? dcfg->cookie_name: DEF_NAME;
    cdomain = dcfg->domain
	?(strcasecmp(dcfg->domain,"none")?dcfg->domain:NULL):DEF_DOMAIN;
    cpath = dcfg->path ? dcfg->path: DEF_PATH;
    cdelta = (dcfg->expires && dcfg->expires>0)?dcfg->expires:DEF_EXPIRES;
    service = dcfg->service ? dcfg->service :
	ntohl(r->connection->local_addr->sa.sin.sin_addr.s_addr);
    p3ph = dcfg->p3p_header ? dcfg->p3p_header : DEF_P3P;

    // put it in host byte order;

    UID_SERVICE(lk) =  service;
    UID_PID(lk) = getpid();
    UID_TIME(lk) = time(NULL);
    UID_SEQ_VER_SET(lk,sequencer,COOKIE_VERSION);
    sequencer++;
    if (sequencer> SEQ_MAX) sequencer = SEQ_MIN;

    // then print
    print_cookie(cbuf,lk);
    apr_table_setn(r->notes, "uid_set", apr_pstrcat(r->pool,cname,"=",cbuf,NULL));
    
    // then recode
    for (i=0; i < sizeof(lk)/sizeof(lk[0]);i++)
	lk[i] = htonl(lk[i]);

    len = apr_base64_encode_len(sizeof(lk));
    cookbuf = (char *) apr_palloc(r->pool, 1 + len);
    apr_base64_encode_binary(cookbuf,(char*)lk,sizeof(lk));
    cookbuf[len] = '\0';
    when = r->request_time/1000000 + cdelta;
    tms = gmtime(&when);
    
    if(!cdomain)
	new_cookie 
	    = apr_psprintf(r->pool,
			  "%s=%s; path=%s; expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
			  cname, cookbuf, cpath,apr_day_snames[tms->tm_wday],
			  tms->tm_mday, apr_month_snames[tms->tm_mon],
			  tms->tm_year % 100,
			  tms->tm_hour, tms->tm_min, tms->tm_sec);
    else 
	new_cookie 
	    = apr_psprintf(r->pool,
			  "%s=%s; path=%s; domain=%s; expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
			  cname, cookbuf,cpath, cdomain,apr_day_snames[tms->tm_wday],
			  tms->tm_mday, apr_month_snames[tms->tm_mon],
			  tms->tm_year % 100,
			  tms->tm_hour, tms->tm_min, tms->tm_sec);

    apr_table_addn(r->headers_out, "Set-Cookie", new_cookie); 
    // put P3P header
    if (p3ph && !apr_table_get(r->headers_out,"P3P") && 
	((dcfg->p3p_enabled == ON && cdomain) ||dcfg->p3p_enabled == ALWAYS ))
	apr_table_setn(r->headers_out,"P3P",p3ph);

    return;
}

static int spot_cookie(request_rec *r)
{
    cookie_dir_rec *dcfg = ap_get_module_config(r->per_dir_config,
						&uid2_module);
    char *cptr;
    char *value;
    char *cname = dcfg->cookie_name ? dcfg->cookie_name : DEF_NAME;

    if ((cptr = (char*)apr_table_get(r->headers_in, "Cookie")))
	if (cname && cptr)
	    {
		char *cend;
		int clen;
		while(1)
		    {
			clen = 0;
			// find exact cookie
			while(*cptr && *cptr==' ')
			    cptr++;
			cend = cptr;
			while(*cend && *cend!=' ' && *cend!='=')
			    {
				cend++;
				clen++;
			    }
			if(clen ==strlen(cname) && !strncmp(cptr,cname,clen))
			    break; // we have cookie name begin in cptr and
			// last char in cend
			cptr=strchr(cptr,';');
			if(!cptr) break;
			cptr++;
			if(!*cptr)
			    {
				cptr = NULL;
				break;
			    }
		    }
		if(cptr && cend)
		    {
			char cbuf[CBUFSIZE];
			char *cookiebuf, *cookieend;
			unsigned int *lk;
			unsigned char *dbuf;
			int dlen;
			// skip leading spaces 	
			while(*cend && *cend==' ')
			    cend++;
			if(*cend == '=') cend++; //leading eq. sign
			// spaces after '='
			while(*cend && *cend==' ')
			    cend++;

                        cookiebuf = apr_pstrdup(r->pool, cend);
			cookieend = strchr(cookiebuf, ';');
			if (cookieend)
			    *cookieend = '\0';      /* Ignore anything after a ; */
			
			dlen = apr_base64_decode_len(cookiebuf);
			dbuf = apr_palloc(r->pool,dlen+16);
			apr_base64_decode_binary(dbuf,cookiebuf);
			lk = (unsigned int*) dbuf;
			// сheck version
			if (UID_VER_GET(lk) == 1) 
			    {
				// old version - do nothing
				;
			    }
			else 
			    {
				// version 2 - should convert to host order
				int i;
				for (i=0;i<4;i++)
				    lk[i] = ntohl(lk[i]);
			    }
			print_cookie(cbuf,lk);
			/* Set the cookie in a note, for logging */
			apr_table_setn(r->notes, "uid_got", 
				      apr_pstrcat(r->pool,cname,"=",cbuf,NULL));
			if(dlen>=4*sizeof(int))
			    return DECLINED;    /* There's already a
						   cookie, no new one
						*/
		    }
	    }
    if (dcfg->enabled == ON || !dcfg->enabled) /* default is to set
						  cookie */
	make_cookie(r,dcfg);
    return DECLINED;
}



static const char *set_cookie_exp(cmd_parms *parms, void *dummy, const char *arg)
{
    cookie_dir_rec *dcfg = dummy;
    time_t mult, mutl2 = 0;
    time_t num = 0;
    char *word;

    /* The simple case first - all numbers (we assume) */
    if (apr_isdigit(arg[0]) && apr_isdigit(arg[strlen(arg) - 1])) {
        dcfg->expires = atol(arg);
        return NULL;
    }

    word = ap_getword_conf(parms->pool, &arg);
    if (!strncasecmp(word, "plus", 1)) {
        word = ap_getword_conf(parms->pool, &arg);
    };

    /* {<num> <type>}* */
    while (word[0]) {
        /* <num> */
	if (apr_isdigit(word[0]))
            num = atoi(word);
        else
            return "bad expiration format, numeric value expected.";

        /* <type> */
        word = ap_getword_conf(parms->pool, &arg);
        if (!word[0])
            return "bad expiration format, expecting months/weeks/days/...>";

        mult = 0;
        if (!strncasecmp(word, "years", 1))
            mult = 60 * 60 * 24 * 365;
        else if (!strncasecmp(word, "months", 2))
            mult = 60 * 60 * 24 * 30;
        else if (!strncasecmp(word, "weeks", 1))
            mult = 60 * 60 * 24 * 7;
        else if (!strncasecmp(word, "days", 1))
            mult = 60 * 60 * 24;
        else if (!strncasecmp(word, "hours", 1))
            mult = 60 * 60;
        else if (!strncasecmp(word, "minutes", 2))
            mult = 60;
        else if (!strncasecmp(word, "seconds", 1))
            mult = 1;
        else
            return "bad expiration format";

        mutl2 = mutl2 + mult * num;

        /* next <num> */
        word = ap_getword_conf(parms->pool, &arg);
    }

    dcfg->expires = mutl2;

    return NULL;
}

static const char *set_cookie_name(cmd_parms *cmd, void *mconfig,
				   const char *name)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;

    dcfg->cookie_name = apr_pstrdup(cmd->pool, name);
    return NULL;
}

static const char *set_service (cmd_parms *cmd, void *mconfig, const char *name)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;
    dcfg->service = atoi(name);
    return NULL;
}

static const char *set_domain (cmd_parms *cmd, void *mconfig, const char *name)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;
    dcfg->domain = apr_pstrdup(cmd->pool, name);
    return NULL;
}

static const char *set_path (cmd_parms *cmd, void *mconfig, const char *name)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;
    dcfg->path = apr_pstrdup(cmd->pool, name);
    return NULL;
}

static const char *set_p3p (cmd_parms *cmd, void *mconfig, const char *arg)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;
    if (!strncasecmp(arg,"On",2))
	dcfg->p3p_enabled = ON;
    else if (!strncasecmp(arg,"Off",3))
	dcfg->p3p_enabled = OFF;
    else if (!strncasecmp(arg,"Always",6))
	dcfg->p3p_enabled = ALWAYS;
    else 
	return "Use On/Off/Always on UIDP3P command";
    return NULL;
}

static const char *set_p3ps (cmd_parms *cmd, void *mconfig, const char *arg)
{
    cookie_dir_rec *dcfg = (cookie_dir_rec *) mconfig;
    dcfg->p3p_header = apr_pstrdup(cmd->pool,arg);
    return NULL;
}

static const char *set_cookie_enable(cmd_parms *cmd, void *mconfig, int arg)
{
    cookie_dir_rec *dcfg = mconfig;
    dcfg->enabled = arg?ON:OFF;
    return NULL;
}

static void uid_init(apr_pool_t *p,server_rec *main_server)
{
  sequencer=SEQ_MIN;
}

static const command_rec uid_cmds[] = {
    AP_INIT_TAKE1("UIDExpires", set_cookie_exp, NULL, OR_FILEINFO,
		  "UID cookie an expiry date code"),
    AP_INIT_FLAG("UIDActive", set_cookie_enable, NULL, OR_FILEINFO,
		 "whether or not to enable UID cookies"),
    AP_INIT_TAKE1("UIDCookieName", set_cookie_name, NULL, OR_FILEINFO,
		  "name of the tracking UID cookie"),
    AP_INIT_TAKE1("UIDService",set_service,NULL,OR_FILEINFO,
		  "UID Cookie service number"),
    AP_INIT_TAKE1("UIDDomain",set_domain,NULL,OR_FILEINFO,
		  "UID Cookie domain name"),
    AP_INIT_TAKE1("UIDPath",set_path,NULL,OR_FILEINFO,
		  "UID Cookie path"),
    AP_INIT_TAKE1("UIDP3P",set_p3p,NULL,OR_FILEINFO,
		  "UID P3P enable"),
    AP_INIT_RAW_ARGS("UIDP3PString",set_p3ps,NULL,OR_FILEINFO,
		 "UID P3P Header value"),
    {NULL}
};

static void * 
merge_uid_dir (apr_pool_t *p, void *basev, void *overridesv)
{
    cookie_dir_rec *base = (cookie_dir_rec *)basev;
    cookie_dir_rec *over = (cookie_dir_rec *)overridesv;
    cookie_dir_rec *dcfg;
    dcfg = (cookie_dir_rec *) apr_pcalloc(p, sizeof(cookie_dir_rec));
    dcfg->enabled	= OVER(enabled);
    dcfg->cookie_name	= OVER(cookie_name);
    dcfg->domain	= OVER(domain);
    dcfg->path		= OVER(path);
    dcfg->expires	= OVER(expires);
    dcfg->service	= OVER(service);
    dcfg->p3p_enabled	= OVER(p3p_enabled);
    dcfg->p3p_header	= OVER(p3p_header);
    return dcfg;
}

static void *make_uid_dir(apr_pool_t *p, char *d)
{
    cookie_dir_rec *dcfg;

    dcfg = (cookie_dir_rec *) apr_pcalloc(p, sizeof(cookie_dir_rec));
    dcfg->enabled	= 0;
    dcfg->cookie_name	= NULL;
    dcfg->domain	= NULL;
    dcfg->path		= NULL;
    dcfg->expires	= 0;
    dcfg->service	= 0;
    dcfg->p3p_enabled	= 0;
    dcfg->p3p_header	= NULL;
    return dcfg;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_child_init(uid_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(spot_cookie, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA uid2_module = { 
    STANDARD20_MODULE_STUFF, 
    make_uid_dir, /* dir config creater */ 
    merge_uid_dir, /* dir merger --- default is to override */ 
    NULL, /* server config */ 
    NULL, /* merge server config */ 
    uid_cmds, /* command table */ 
    register_hooks /* register_handlers */ 
}; 

#if 0
module MODULE_VAR_EXPORT uid2_module = {
    STANDARD_MODULE_STUFF,
    uid_init,                   /* initializer */
    make_uid_dir,		/* dir config creater */
    merge_uid_dir,		/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server configs */
    uid_cmds,			/* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    spot_cookie,                /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
#endif

