#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <fuse.h>
#include <fuse/fuse_common.h>
#include <fuse/fuse_lowlevel.h>

struct fusedata;
extern struct fuse_session *fuse_get_session(struct fuse *f);

typedef struct fuse_chan *Fuse_Channel;

#if defined(__linux__) || defined(__APPLE__)
# include <sys/xattr.h>
#else
# define XATTR_CREATE 1
# define XATTR_REPLACE 2
#endif

#if defined(__linux__) || defined(__sun__)
# define STAT_SEC(st, st_xtim) ((st)->st_xtim.tv_sec)
# define STAT_NSEC(st, st_xtim) ((st)->st_xtim.tv_nsec)
#else
# define STAT_SEC(st, st_xtim) ((st)->st_xtim##espec.tv_sec)
# define STAT_NSEC(st, st_xtim) ((st)->st_xtim##espec.tv_nsec)
#endif

/* Implement a macro to handle multiple formats (integer, float, and array
 * containing seconds and nanoseconds). */
#define PULL_TIME(st, st_xtim, svp)					\
{									\
	SV *sv = svp;							\
	if (SvROK(sv)) {						\
		AV *av = (AV *)SvRV(sv);				\
		if (SvTYPE((SV *)av) != SVt_PVAV) {			\
			Perl_croak_nocontext("Reference was not array ref"); \
		}							\
		if (av_len(av) != 1) {					\
			Perl_croak_nocontext("Array of incorrect dimension"); \
		}							\
		STAT_SEC(st, st_xtim) = SvIV(*(av_fetch(av, 0, FALSE))); \
		STAT_NSEC(st, st_xtim) = SvIV(*(av_fetch(av, 1, FALSE))); \
	}								\
	else if (SvNOK(sv) || SvIOK(sv) || SvPOK(sv)) {			\
		double tm = SvNV(sv);					\
		STAT_SEC(st, st_xtim) = (int)tm;			\
		STAT_NSEC(st, st_xtim) = (tm - (int)tm) * 1000000000;	\
	}								\
	else {								\
		Perl_croak_nocontext("Invalid data type passed");	\
	}								\
}

/* Determine if threads support should be included */
#ifdef USE_ITHREADS
# ifdef I_PTHREAD
#  define FUSE_USE_ITHREADS
#  if (PERL_VERSION < 8) || (PERL_VERSION == 8 && PERL_SUBVERSION < 9)
#    define tTHX PerlInterpreter*
#    define STR_WITH_LEN(s)  ("" s ""), (sizeof(s)-1)
#    define hv_fetchs(hv,key,lval) Perl_hv_fetch(aTHX_ hv, STR_WITH_LEN(key), lval)
#    define dMY_CXT_INTERP(interp) \
	SV *my_cxt_sv = *hv_fetchs(interp->Imodglobal, MY_CXT_KEY, TRUE); \
	my_cxt_t *my_cxtp = INT2PTR(my_cxt_t*, SvUV(my_cxt_sv))
#  endif
# else
#  warning "Sorry, I don't know how to handle ithreads on this architecture. Building non-threaded version"
# endif
#endif

/* Global Data */

#define MY_CXT_KEY "Fuse::_guts" XS_VERSION
#if FUSE_VERSION >= 29
# if FUSE_FOUND_MICRO_VER >= 1
#  define N_CALLBACKS 45
# else /* FUSE_FOUND_MICRO_VER < 1 */
#  define N_CALLBACKS 44
# endif
#elif FUSE_VERSION >= 28
# define N_CALLBACKS 41
#else /* FUSE_VERSION < 28 */
# define N_CALLBACKS 38
#endif
#define N_FLAGS 8

typedef struct fusedata
{	struct fuse *fuse;
	struct fuse_chan *ch;
	struct fuse_session *se;
	char *mountpoint;
	int bufsize;
	struct fuse_operations *fops;

	int threaded;
	SV *private_data;
	SV *callback[N_CALLBACKS];
	HV *handles;
	int utimens_as_array;

	tTHX creator;
} *  Fuse_Context;

typedef struct {
#ifdef USE_ITHREADS
	tTHX self;
#endif
	HV *fuse_contexts;
} my_cxt_t;
START_MY_CXT;


Fuse_Context find_fuse_context(pTHX_ pMY_CXT_ const char *in)
{
	SV **ret = hv_fetch(MY_CXT.fuse_contexts, in, strlen(in), 0);

	if (!ret) {
		croak("no context found for %s", in);
	}

	SV *contextsv = *ret;
	Fuse_Context context;
	if (sv_derived_from(contextsv, "Fuse::Context")) {
		IV tmp = SvIV((SV*)SvRV(contextsv));
		context = INT2PTR(Fuse_Context, tmp);
	}
	else
		croak("context is not of type Fuse::Context");

	if (context->creator != aTHX)
		croak("context is for the wrong thread!");

	return context;
}

# define FUSE_CONTEXT_PRE dTHX; dMY_CXT; Fuse_Context context = find_fuse_context(aTHX_ aMY_CXT_ fuse_get_context()->private_data); PERL_UNUSED_VAR(my_cxtp); dSP;
# define FUSE_CONTEXT_POST

#undef DEBUGf
#if 0
#define DEBUGf(f, a...) fprintf(stderr, "%s:%d (%li): " f,__BASE_FILE__,__LINE__,sp-PL_stack_base ,##a )
#else
#define DEBUGf(a...)
#endif

#define FH_KEY(context,fi) sv_2mortal(newSViv((fi)->fh))
#define FH_GETHANDLE(context,fi) S_fh_get_handle(aTHX_ aMY_CXT_ context, fi)
#define FH_STOREHANDLE(context,fi,sv) S_fh_store_handle(aTHX_ aMY_CXT_ context, fi, sv)
#define FH_RELEASEHANDLE(context,fi) S_fh_release_handle(aTHX_ aMY_CXT_ context, fi)

SV *S_fh_get_handle(pTHX_ pMY_CXT_ Fuse_Context context, struct fuse_file_info *fi) {
	SV *val;
	val = &PL_sv_undef;
	if(fi->fh != 0) {
		HE *he;
		if((he = hv_fetch_ent(context->handles, FH_KEY(context,fi), 0, 0))) {
			val = HeVAL(he);
			SvGETMAGIC(val);
		}
	}
	return val;
}

void S_fh_release_handle(pTHX_ pMY_CXT_ Fuse_Context context, struct fuse_file_info *fi) {
	if(fi->fh != 0) {
		(void)hv_delete_ent(context->handles, FH_KEY(context,fi), G_DISCARD, 0);
		fi->fh = 0;
	}
}

void S_fh_store_handle(pTHX_ pMY_CXT_ Fuse_Context context, struct fuse_file_info *fi, SV *sv) {
	if(SvOK(sv)) {
#ifdef FUSE_USE_ITHREADS
		if(context->threaded) {
			SvSHARE(sv);
		}
#endif
        /* This seems to be screwing things up... */
		// MAGIC *mg = (SvTYPE(sv) == SVt_PVMG) ? mg_find(sv, PERL_MAGIC_shared_scalar) : NULL;
		// fi->fh = mg ? PTR2IV(mg->mg_ptr) : PTR2IV(sv);
		fi->fh = PTR2IV(sv);
		if(hv_store_ent(context->handles, FH_KEY(context,fi), SvREFCNT_inc(sv), 0) == NULL) {
			SvREFCNT_dec(sv);
		}
		SvSETMAGIC(sv);
	}
}

int _PLfuse_getattr(const char *file, struct stat *result) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("getattr begin: %s\n",file);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,strlen(file))));
	PUTBACK;
	rv = call_sv(context->callback[0],G_ARRAY);
	SPAGAIN;
	if(rv != 13) {
		if(rv > 1) {
			fprintf(stderr,"inappropriate number of returned values from getattr\n");
			rv = -ENOSYS;
		} else if(rv)
			rv = POPi;
		else
			rv = -ENOENT;
	} else {
		result->st_blocks = POPi;
		result->st_blksize = POPi;
		PULL_TIME(result, st_ctim, POPs);
		PULL_TIME(result, st_mtim, POPs);
		PULL_TIME(result, st_atim, POPs);
		result->st_size = POPn;	// we pop double here to support files larger than 4Gb (long limit)
		result->st_rdev = POPi;
		result->st_gid = POPi;
		result->st_uid = POPi;
		result->st_nlink = POPi;
		result->st_mode = POPi;
		result->st_ino   = POPi;
		result->st_dev = POPi;
		rv = 0;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("getattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_readlink(const char *file,char *buf,size_t buflen) {
	int rv;
	if(buflen < 1)
		return EINVAL;
	FUSE_CONTEXT_PRE;
	DEBUGf("readlink begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(context->callback[1],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else {
		SV *mysv = POPs;
		if(SvTYPE(mysv) == SVt_IV || SvTYPE(mysv) == SVt_NV)
			rv = SvIV(mysv);
		else {
			strncpy(buf,SvPV_nolen(mysv),buflen);
			rv = 0;
		}
	}
	FREETMPS;
	LEAVE;
	buf[buflen-1] = 0;
	PUTBACK;
	DEBUGf("readlink end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_getdir(const char *file, fuse_dirh_t dirh, fuse_dirfil_t dirfil) {
	int prv, rv;
	SV **swp;
	FUSE_CONTEXT_PRE;
	DEBUGf("getdir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	prv = call_sv(context->callback[2],G_ARRAY);
	SPAGAIN;
	if(prv) {
		/* Should yield the bottom of the current stack... */
		swp = SP - prv + 1;
		rv = POPi;
		/* Sort of a hack to walk the stack in order, instead of reverse
		 * order - trying to explain to potential users why they need to
		 * reverse the order of this array would be confusing, at best. */
		while (swp <= SP)
			dirfil(dirh,SvPVx_nolen(*(swp++)),0,0);
		SP -= prv - 1;
	} else {
		fprintf(stderr,"getdir() handler returned nothing!\n");
		rv = -ENOSYS;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("getdir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_mknod (const char *file, mode_t mode, dev_t dev) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("mknod begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	XPUSHs(sv_2mortal(newSViv(dev)));
	PUTBACK;
	rv = call_sv(context->callback[3],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("mknod end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_mkdir (const char *file, mode_t mode) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("mkdir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	PUTBACK;
	rv = call_sv(context->callback[4],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("mkdir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_unlink (const char *file) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("unlink begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(context->callback[5],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("unlink end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_rmdir (const char *file) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("rmdir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(context->callback[6],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("rmdir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_symlink (const char *file, const char *new) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("symlink begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(context->callback[7],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("symlink end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_rename (const char *file, const char *new) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("rename begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(context->callback[8],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("rename end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_link (const char *file, const char *new) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("link begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(context->callback[9],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("link end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_chmod (const char *file, mode_t mode) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("chmod begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	PUTBACK;
	rv = call_sv(context->callback[10],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("chmod end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_chown (const char *file, uid_t uid, gid_t gid) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("chown begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(uid)));
	XPUSHs(sv_2mortal(newSViv(gid)));
	PUTBACK;
	rv = call_sv(context->callback[11],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("chown end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_truncate (const char *file, off_t off) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("truncate begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	PUTBACK;
	rv = call_sv(context->callback[12],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("truncate end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_utime (const char *file, struct utimbuf *uti) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("utime begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(uti->actime)));
	XPUSHs(sv_2mortal(newSViv(uti->modtime)));
	PUTBACK;
	rv = call_sv(context->callback[13],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("utime end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_open (const char *file, struct fuse_file_info *fi) {
	int rv;
	int flags = fi->flags;
	HV *fihash;
	FUSE_CONTEXT_PRE;
	DEBUGf("open begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(flags)));
	/* Create a hashref containing the details from fi
	 * which we can look at or modify.
	 */
	fi->fh = 0; /* Ensure it starts with 0 - important if they don't set it */
	fihash = newHV();
	(void) hv_store(fihash, "direct_io",    9, newSViv(fi->direct_io),   0);
	(void) hv_store(fihash, "keep_cache",  10, newSViv(fi->keep_cache),  0);
#if FUSE_VERSION >= 28
	(void) hv_store(fihash, "nonseekable", 11, newSViv(fi->nonseekable), 0);
#endif
	XPUSHs(sv_2mortal(newRV_noinc((SV*) fihash)));
	/* All hashref things done */

	PUTBACK;
	/* Open called with filename, flags */
	rv = call_sv(context->callback[14],G_ARRAY);
	SPAGAIN;
	if(rv) {
		if(rv > 1) {
			SV *sv = newSVsv(POPs);
			SvSHARE(sv);
			FH_STOREHANDLE(context,fi,sv);
		}
		rv = POPi;
	}
	else
		rv = 0;
	if (rv == 0)
	{
		/* Success, so copy the file handle which they returned */
		SV **svp;
		if ((svp = hv_fetch(fihash, "direct_io",    9, 0)) != NULL)
			fi->direct_io   = SvIV(*svp);
		if ((svp = hv_fetch(fihash, "keep_cache",  10, 0)) != NULL)
			fi->keep_cache  = SvIV(*svp);
#if FUSE_VERSION >= 28
		if ((svp = hv_fetch(fihash, "nonseekable", 11, 0)) != NULL)
 			fi->nonseekable = SvIV(*svp);
#endif
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("open end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_read (const char *file, char *buf, size_t buflen, off_t off,
		struct fuse_file_info *fi) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("read begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(buflen)));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[15],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else {
		SV *mysv = POPs;
		if(SvTYPE(mysv) == SVt_NV || SvTYPE(mysv) == SVt_IV)
			rv = SvIV(mysv);
		else {
			if(SvPOK(mysv)) {
				rv = SvCUR(mysv);
			} else {
				rv = 0;
			}
			if(rv > buflen)
				croak("read() handler returned more than buflen! (%i > %i)",rv,buflen);
			if(rv)
				memcpy(buf,SvPV_nolen(mysv),rv);
		}
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("read end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_write (const char *file, const char *buf, size_t buflen, off_t off, struct fuse_file_info *fi) {
	int rv;
	SV *sv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("write begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
#if (PERL_VERSION < 8) || (PERL_VERSION == 8 && PERL_SUBVERSION < 9)
	sv = newSV(0);
	sv_upgrade(sv, SVt_PV);
#else
	sv = newSV_type(SVt_PV);
#endif
	SvPV_set(sv, (char *)buf);
	SvLEN_set(sv, 0);
	SvCUR_set(sv, buflen);
	SvPOK_on(sv);
	SvREADONLY_on(sv);
	XPUSHs(sv_2mortal(sv));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[16],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("write end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_statfs (const char *file, struct statvfs *st) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("statfs begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	rv = call_sv(context->callback[17],G_ARRAY);
	SPAGAIN;
	DEBUGf("statfs got %i params\n",rv);
	if(rv == 6 || rv == 7) {
		st->f_bsize	= POPi;
		st->f_bfree	= POPi;
		st->f_blocks	= POPi;
		st->f_ffree	= POPi;
		st->f_files	= POPi;
		st->f_namemax	= POPi;
		/* zero and fill-in other */
		st->f_fsid = 0;
		st->f_flag = 0;
		st->f_frsize = st->f_bsize;
		st->f_bavail = st->f_bfree;
		st->f_favail = st->f_ffree;

		if(rv == 7)
			rv = POPi;
		else
			rv = 0;
	} else
	if(rv > 1)
		croak("inappropriate number of returned values from statfs");
	else
	if(rv)
		rv = POPi;
	else
		rv = -ENOSYS;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("statfs end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_flush (const char *file, struct fuse_file_info *fi) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("flush begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[18],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("flush end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_release (const char *file, struct fuse_file_info *fi) {
	int rv;
	int flags = fi->flags;
#if FUSE_VERSION >= 29 && !defined(PERL_HAS_64BITINT)
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("release begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(flags)));
	XPUSHs(FH_GETHANDLE(context,fi));
#if FUSE_VERSION >= 29
	XPUSHs(fi->flock_release ? sv_2mortal(newSViv(1)) : &PL_sv_undef);
# ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(fi->lock_owner)));
# else
	if (asprintf(&temp, "%llu", fi->lock_owner) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
# endif
#endif
	PUTBACK;
	rv = call_sv(context->callback[19],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FH_RELEASEHANDLE(context,fi);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("release end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_fsync (const char *file, int datasync, struct fuse_file_info *fi) {
	int rv;
	int flags = fi->flags;
	FUSE_CONTEXT_PRE;
	DEBUGf("fsync begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(flags)));
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[20],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("fsync end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

#ifdef __APPLE__
int _PLfuse_setxattr (const char *file, const char *name, const char *buf, size_t buflen, int flags, uint32_t position) {
#else
int _PLfuse_setxattr (const char *file, const char *name, const char *buf, size_t buflen, int flags) {
#endif
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("setxattr begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(name,0)));
	XPUSHs(sv_2mortal(newSVpvn(buf,buflen)));
	XPUSHs(sv_2mortal(newSViv(flags)));
	PUTBACK;
	rv = call_sv(context->callback[21],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("setxattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

#ifdef __APPLE__
int _PLfuse_getxattr (const char *file, const char *name, char *buf, size_t buflen, uint32_t position) {
#else
int _PLfuse_getxattr (const char *file, const char *name, char *buf, size_t buflen) {
#endif
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("getxattr begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(name,0)));
	PUTBACK;
	rv = call_sv(context->callback[22],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else {
		SV *mysv = POPs;

		rv = 0;
		if(SvTYPE(mysv) == SVt_NV || SvTYPE(mysv) == SVt_IV)
			rv = SvIV(mysv);
		else {
			if(SvPOK(mysv)) {
				rv = SvCUR(mysv);
			} else {
				rv = 0;
			}
			if ((rv > 0) && (buflen > 0))
			{
				if(rv > buflen)
					rv = -ERANGE;
				else
					memcpy(buf,SvPV_nolen(mysv),rv);
			}
		}
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("getxattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_listxattr (const char *file, char *list, size_t size) {
	int prv, rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("listxattr begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	prv = call_sv(context->callback[23],G_ARRAY);
	SPAGAIN;
	if(!prv)
		rv = -ENOENT;
	else {

		char *p = list;
		int spc = size;
		int total_len = 0;

		rv = POPi;
		prv--;

		/* Always nul terminate */
		if (list && (size > 0))
			list[0] = '\0';

		while (prv > 0)
		{
			SV *mysv = POPs;
			prv--;

			if (SvPOK(mysv)) {
				/* Copy nul too */
				int s = SvCUR(mysv) + 1;
				total_len += s;

				if (p && (size > 0) && (spc >= s))
				{
					memcpy(p,SvPV_nolen(mysv),s);
					p += s;
					spc -= s;
				}
			}
		}

		/*
		 * If the Perl returned an error, return that.
		 * Otherwise check that the buffer was big enough.
		 */
		if (rv == 0)
		{
			rv = total_len;
			if ((size > 0) && (size < total_len))
				rv = -ERANGE;
		}
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("listxattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_removexattr (const char *file, const char *name) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("removexattr begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(name,0)));
	PUTBACK;
	rv = call_sv(context->callback[24],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("removexattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_opendir(const char *file, struct fuse_file_info *fi) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("opendir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	fi->fh = 0; /* Ensure it starts with 0 - important if they don't set it */
	PUTBACK;
	rv = call_sv(context->callback[25], G_ARRAY);
	SPAGAIN;
	if (rv) {
		if (rv > 1) {
			SV *sv = newSVsv(POPs);
			SvSHARE(sv);
			FH_STOREHANDLE(context,fi,sv);
		}
		rv = POPi;
	} else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("opendir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_readdir(const char *file, void *dirh, fuse_fill_dir_t dirfil,
                    off_t off, struct fuse_file_info *fi) {
	int prv = 0, rv;
	SV *sv, **svp, **swp;
	AV *av, *av2;
	struct stat st;
	bool st_filled = 0;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("readdir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	prv = call_sv(context->callback[26],G_ARRAY);
	SPAGAIN;
	if (prv) {
		/* Should yield the bottom of the current stack... */
		swp = SP - prv + 1;
		rv = POPi;
		memset(&st, 0, sizeof(struct stat));
		/* Sort of a hack to walk the stack in order, instead of reverse
		 * order - trying to explain to potential users why they need to
		 * reverse the order of this array would be confusing, at best. */
		while (swp <= SP) {
			sv = *(swp++);
			if (!SvROK(sv) && SvPOK(sv))
			/* Just a bare SV (probably a string; hopefully a string) */
				dirfil(dirh, SvPVx_nolen(sv), NULL, 0);
			else if (SvROK(sv) && SvTYPE(av = (AV *)SvRV(sv)) == SVt_PVAV) {
				if (av_len(av) >= 2) {
					/* The third element of the array should be the args that
					 * would otherwise go to getattr(); a lot of filesystems
					 * will, or at least can, return that info as part of the
					 * enumeration process... */
					svp = av_fetch(av, 2, FALSE);
					if (SvROK(*svp) &&
					    SvTYPE(av2 = (AV *)SvRV(*svp)) == SVt_PVAV &&
					    av_len(av2) == 12) {
						st.st_dev     = SvIV(*(av_fetch(av2,  0, FALSE)));
						st.st_ino     = SvIV(*(av_fetch(av2,  1, FALSE)));
						st.st_mode    = SvIV(*(av_fetch(av2,  2, FALSE)));
						st.st_nlink   = SvIV(*(av_fetch(av2,  3, FALSE)));
						st.st_uid     = SvIV(*(av_fetch(av2,  4, FALSE)));
						st.st_gid     = SvIV(*(av_fetch(av2,  5, FALSE)));
						st.st_rdev    = SvIV(*(av_fetch(av2,  6, FALSE)));
						st.st_size    = SvNV(*(av_fetch(av2,  7, FALSE)));
						PULL_TIME(&st, st_atim, *(av_fetch(av2,  8, FALSE)));
						PULL_TIME(&st, st_mtim, *(av_fetch(av2,  9, FALSE)));
						PULL_TIME(&st, st_ctim, *(av_fetch(av2, 10, FALSE)));
						st.st_blksize = SvIV(*(av_fetch(av2, 11, FALSE)));
						st.st_blocks  = SvIV(*(av_fetch(av2, 12, FALSE)));
						st_filled = 1;
					}
					else
						fprintf(stderr,"Extra SV didn't appear to be correct, ignoring\n");
					/* For now if the element isn't what we want, just
					 * quietly ignore it... */
				}
				if (av_len(av) >= 1) {
					char *entryname = SvPVx_nolen(*(av_fetch(av, 1, FALSE)));
					off_t elemnum = SvNV(*(av_fetch(av, 0, FALSE)));
					dirfil(dirh, entryname, st_filled ? &st : NULL, elemnum);
				}
				if (st_filled) {
					memset(&st, 0, sizeof(struct stat));
					st_filled = 0;
				}
			}
			else
				fprintf(stderr, "ERROR: Unknown entry passed via readdir\n");
		}
		SP -= prv - 1;
	} else {
		fprintf(stderr,"readdir() handler returned nothing!\n");
		rv = -ENOSYS;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("readdir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_releasedir(const char *file, struct fuse_file_info *fi) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("releasedir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[27], G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FH_RELEASEHANDLE(context,fi);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("releasedir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_fsyncdir(const char *file, int datasync,
                     struct fuse_file_info *fi) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("fsyncdir begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(datasync)));
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[28], G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("fsyncdir end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

void *_PLfuse_init(struct fuse_conn_info *fc)
{
	void *rv = NULL;
	int prv;
	FUSE_CONTEXT_PRE;
	DEBUGf("init begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	prv = call_sv(context->callback[29], G_SCALAR);
	SPAGAIN;
	if (prv) {
		rv = POPs;
		if (rv == &PL_sv_undef)
			context->private_data = NULL;
		else
			context->private_data = SvREFCNT_inc((SV *)rv);
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("init end: %p\n", rv);
	FUSE_CONTEXT_POST;
	return context;
}

void _PLfuse_destroy(void *private_data) {
	FUSE_CONTEXT_PRE;
	DEBUGf("destroy begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(context->private_data ? (SV *)context->private_data : &PL_sv_undef);
	PUTBACK;
	call_sv(context->callback[30], G_VOID);
	SPAGAIN;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("destroy end\n");
	FUSE_CONTEXT_POST;
}

int _PLfuse_access(const char *file, int mask) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("access begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mask)));
	PUTBACK;
	rv = call_sv(context->callback[31], G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("access end: %d\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_create(const char *file, mode_t mode, struct fuse_file_info *fi) {
	int rv;
	HV *fihash;
	FUSE_CONTEXT_PRE;
	DEBUGf("create begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	XPUSHs(sv_2mortal(newSViv(fi->flags)));
	fi->fh = 0; /* Ensure it starts with 0 - important if they don't set it */
	/* Create a hashref containing the details from fi
	 * which we can look at or modify.
	 */
	fihash = newHV();
	(void) hv_store(fihash, "direct_io",    9, newSViv(fi->direct_io),   0);
	(void) hv_store(fihash, "keep_cache",  10, newSViv(fi->keep_cache),  0);
#if FUSE_VERSION >= 28
	(void) hv_store(fihash, "nonseekable", 11, newSViv(fi->nonseekable), 0);
#endif
	XPUSHs(sv_2mortal(newRV_noinc((SV*) fihash)));
	/* All hashref things done */

	PUTBACK;
	rv = call_sv(context->callback[32], G_ARRAY);
	SPAGAIN;
	if (rv) {
		if (rv > 1) {
			SV *sv = newSVsv(POPs);
			SvSHARE(sv);
			FH_STOREHANDLE(context,fi,sv);
		}
		rv = POPi;
	}
	else {
		fprintf(stderr, "create() handler returned nothing!\n");
		rv = -ENOSYS;
	}
	if (rv == 0) {
		/* Success, so copy the file handle which they returned */
		SV **svp;
		if ((svp = hv_fetch(fihash, "direct_io",    9, 0)) != NULL)
			fi->direct_io   = SvIV(*svp);
		if ((svp = hv_fetch(fihash, "keep_cache",  10, 0)) != NULL)
			fi->keep_cache  = SvIV(*svp);
#if FUSE_VERSION >= 28
		if ((svp = hv_fetch(fihash, "nonseekable", 11, 0)) != NULL)
			fi->nonseekable = SvIV(*svp);
#endif
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("create end: %d\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_ftruncate(const char *file, off_t off, struct fuse_file_info *fi) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("ftruncate begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[33],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("ftruncate end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_fgetattr(const char *file, struct stat *result,
                     struct fuse_file_info *fi) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("fgetattr begin: %s\n",file);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[34],G_ARRAY);
	SPAGAIN;
	if(rv != 13) {
		if(rv > 1) {
			fprintf(stderr,"inappropriate number of returned values from getattr\n");
			rv = -ENOSYS;
		} else if(rv)
			rv = POPi;
		else
			rv = -ENOENT;
	} else {
		result->st_blocks = POPi;
		result->st_blksize = POPi;
		PULL_TIME(result, st_ctim, POPs);
		PULL_TIME(result, st_mtim, POPs);
		PULL_TIME(result, st_atim, POPs);
		result->st_size = POPn;	// we pop double here to support files larger than 4Gb (long limit)
		result->st_rdev = POPi;
		result->st_gid = POPi;
		result->st_uid = POPi;
		result->st_nlink = POPi;
		result->st_mode = POPi;
		result->st_ino   = POPi;
		result->st_dev = POPi;
		rv = 0;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("fgetattr end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_lock(const char *file, struct fuse_file_info *fi, int cmd,
                 struct flock *lockinfo) {
	int rv;
	HV *lihash;
	SV *sv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("lock begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(cmd)));
	lihash = newHV();
	if (lockinfo) {
		(void) hv_store(lihash, "l_type",   6, newSViv(lockinfo->l_type), 0);
		(void) hv_store(lihash, "l_whence", 8, newSViv(lockinfo->l_whence), 0);
#ifdef PERL_HAS_64BITINT
		sv = newSViv(lockinfo->l_start);
#else
		if (asprintf(&temp, "%llu", lockinfo->l_start) == -1)
			croak("Memory allocation failure!");
		sv = newSVpv(temp, 0);
		free(temp);
#endif
		(void) hv_store(lihash, "l_start",  7, sv, 0);
#ifdef PERL_HAS_64BITINT
		sv = newSViv(lockinfo->l_len);
#else
		if (asprintf(&temp, "%llu", lockinfo->l_len) == -1)
			croak("Memory allocation failure!");
		sv = newSVpv(temp, 0);
		free(temp);
#endif
		(void) hv_store(lihash, "l_len",    5, sv, 0);
		(void) hv_store(lihash, "l_pid",    5, newSViv(lockinfo->l_pid), 0);
	}
	XPUSHs(sv_2mortal(newRV_noinc((SV*) lihash)));
	XPUSHs(FH_GETHANDLE(context,fi));

	PUTBACK;
	rv = call_sv(context->callback[35],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	if (lockinfo && !rv) {
		/* Need to copy back any altered values from the hash into
		 * the struct... */
		SV **svp;
		if ((svp = hv_fetch(lihash, "l_type",   6, 0)) != NULL)
			lockinfo->l_type   = SvIV(*svp);
		if ((svp = hv_fetch(lihash, "l_whence", 8, 0)) != NULL)
			lockinfo->l_whence = SvIV(*svp);
		if ((svp = hv_fetch(lihash, "l_start",  7, 0)) != NULL)
			lockinfo->l_start  = SvNV(*svp);
		if ((svp = hv_fetch(lihash, "l_len",    5, 0)) != NULL)
			lockinfo->l_len    = SvNV(*svp);
		if ((svp = hv_fetch(lihash, "l_pid",    5, 0)) != NULL)
			lockinfo->l_pid    = SvIV(*svp);
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("lock end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_utimens(const char *file, const struct timespec tv[2]) {
	int rv;
	FUSE_CONTEXT_PRE;
	DEBUGf("utimens begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	if (context->utimens_as_array) {
		/* Pushing timespecs as 2-element arrays (if tv is present). */
		AV *av;
		if (tv) {
			av = newAV();
			av_push(av, newSViv(tv[0].tv_sec));
			av_push(av, newSViv(tv[0].tv_nsec));
			XPUSHs(sv_2mortal(newRV_noinc((SV *)av)));
			av = newAV();
			av_push(av, newSViv(tv[1].tv_sec));
			av_push(av, newSViv(tv[1].tv_nsec));
			XPUSHs(sv_2mortal(newRV_noinc((SV *)av)));
		}
		else {
			XPUSHs(&PL_sv_undef);
			XPUSHs(&PL_sv_undef);
		}

	}
	else {
		/* Pushing timespecs as floating point (double) values. */
		XPUSHs(tv ? sv_2mortal(newSVnv(tv[0].tv_sec + (tv[0].tv_nsec / 1000000000.0))) : &PL_sv_undef);
		XPUSHs(tv ? sv_2mortal(newSVnv(tv[1].tv_sec + (tv[1].tv_nsec / 1000000000.0))) : &PL_sv_undef);
	}
	PUTBACK;
	rv = call_sv(context->callback[36],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("utimens end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_bmap(const char *file, size_t blocksize, uint64_t *idx) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("bmap begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(blocksize)));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(*idx)));
#else
	if (asprintf(&temp, "%llu", *idx) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	PUTBACK;
	rv = call_sv(context->callback[37],G_ARRAY);
	SPAGAIN;
	if (rv > 0 && rv < 3) {
		if (rv == 2)
			*idx = POPn;
		rv = POPi;
	}
	else {
		fprintf(stderr, "bmap(): wrong number of values returned?\n");
		rv = -ENOSYS;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("bmap end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

#if FUSE_VERSION >= 28

# ifndef __linux__
#  define _IOC_SIZE(n) IOCPARM_LEN(n)
# endif

int _PLfuse_ioctl(const char *file, int cmd, void *arg,
                  struct fuse_file_info *fi, unsigned int flags, void *data) {
	int rv;
	SV *sv = NULL;
	FUSE_CONTEXT_PRE;
	DEBUGf("ioctl begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	/* I don't know why cmd is a signed int in the first place;
	 * casting as unsigned so stupid tricks don't have to be done on
	 * the perl side */
	XPUSHs(sv_2mortal(newSVuv((unsigned int)cmd)));
	XPUSHs(sv_2mortal(newSViv(flags)));
	if (cmd & IOC_IN)
		XPUSHs(sv_2mortal(newSVpvn(data, _IOC_SIZE(cmd))));
	else
		XPUSHs(&PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[39],G_ARRAY);
	SPAGAIN;
	if ((cmd & IOC_OUT) && (rv == 2)) {
		sv = POPs;
		rv--;
	}

	if (rv > 0)
		rv = POPi;

	if ((cmd & IOC_OUT) && !rv) {
		if (sv) {
			size_t len;
			char *rdata = SvPV(sv, len);

			if (len > _IOC_SIZE(cmd)) {
				fprintf(stderr, "ioctl(): returned data was too large for data area\n");
				rv = -EFBIG;
			}
			else {
				memset(data, 0, _IOC_SIZE(cmd));
				memcpy(data, rdata, len);
			}
		}
		else {
			fprintf(stderr, "ioctl(): ioctl was a read op, but no data was returned from call?\n");
			rv = -EFAULT;
		}
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("ioctl end: %i\n",rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_poll(const char *file, struct fuse_file_info *fi,
                 struct fuse_pollhandle *ph, unsigned *reventsp) {
	int rv;
	SV *sv = NULL;
	FUSE_CONTEXT_PRE;
	DEBUGf("poll begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	if (ph) {
		/* Still gotta figure out how to do this right... */
		sv = newSViv(PTR2IV(ph));
		SvREADONLY_on(sv);
		SvSHARE(sv);
		XPUSHs(sv);
	}
	else
		XPUSHs(&PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(*reventsp)));
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;
	rv = call_sv(context->callback[40],G_ARRAY);
	SPAGAIN;
	if (rv > 1) {
		*reventsp = POPi;
		rv--;
	}
	rv = (rv ? POPi : 0);
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("poll end: %i\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}
#endif /* FUSE_VERSION >= 28 */

#if FUSE_VERSION >= 29
int _PLfuse_write_buf (const char *file, struct fuse_bufvec *buf, off_t off,
                       struct fuse_file_info *fi) {
	int rv, i;
	HV *bvhash;
	AV *bvlist;
	SV *sv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("write_buf begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	bvlist = newAV();
	for (i = 0; i < buf->count; i++) {
		bvhash = newHV();
		sv = newSViv(buf->buf[i].size);
		(void) hv_store(bvhash, "size",  4, sv, 0);
		sv = newSViv(buf->buf[i].flags);
		(void) hv_store(bvhash, "flags", 5, sv, 0);
		sv = &PL_sv_undef;
		if (!(buf->buf[i].flags & FUSE_BUF_IS_FD)) {
#if (PERL_VERSION < 8) || (PERL_VERSION == 8 && PERL_SUBVERSION < 9)
			sv = newSV(0);
			sv_upgrade(sv, SVt_PV);
#else
			sv = newSV_type(SVt_PV);
#endif
			SvPV_set(sv, (char *)buf->buf[i].mem);
			SvLEN_set(sv, 0);
			SvCUR_set(sv, buf->buf[i].size);
			SvPOK_on(sv);
			SvREADONLY_on(sv);
		}
		(void) hv_store(bvhash, "mem",   3, sv, 0); 
		sv = newSViv(buf->buf[i].fd);
		(void) hv_store(bvhash, "fd",    2, sv, 0);
		sv = newSViv(buf->buf[i].pos);
		(void) hv_store(bvhash, "pos",   3, sv, 0);
		av_push(bvlist, newRV((SV *)bvhash));
	}
	XPUSHs(sv_2mortal(newRV_noinc((SV *)bvlist)));
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;

	rv = call_sv(context->callback[41], G_SCALAR);
	SPAGAIN;
	rv = rv ? POPi : -ENOENT;

	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("write_buf end: %i\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_read_buf (const char *file, struct fuse_bufvec **bufp, size_t size,
                      off_t off, struct fuse_file_info *fi) {
	int rv;
	HV *bvhash;
	AV *bvlist;
	struct fuse_bufvec *src;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("read_buf begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(size)));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(off)));
#else
	if (asprintf(&temp, "%llu", off) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	free(temp);
#endif
	bvlist = newAV();
	bvhash = newHV();
	(void) hv_store(bvhash, "size",  4, newSViv(size),   0);
	(void) hv_store(bvhash, "flags", 5, newSViv(0),      0);
	(void) hv_store(bvhash, "mem",   3, newSVpv("", 0),  0);
	(void) hv_store(bvhash, "fd",    2, newSViv(-1),     0);
	(void) hv_store(bvhash, "pos",   3, newSViv(0),      0);
	av_push(bvlist, newRV((SV *)bvhash));
	XPUSHs(sv_2mortal(newRV_noinc((SV*) bvlist)));
	XPUSHs(FH_GETHANDLE(context,fi));
	PUTBACK;

	rv = call_sv(context->callback[42], G_SCALAR);
	SPAGAIN;
	if (!rv)
		rv = -ENOENT;
	else {
		SV **svp;
		int i;

		rv = POPi;
		if (rv < 0)
			goto READ_BUF_FAIL;

		src = malloc(sizeof(struct fuse_bufvec) +
		    (av_len(bvlist) * sizeof(struct fuse_buf)));
		if (src == NULL)
			croak("Memory allocation failure!");
		*src = FUSE_BUFVEC_INIT(0);
		src->count = av_len(bvlist) + 1;
		for (i = 0; i <= av_len(bvlist); i++) {
			svp = av_fetch(bvlist, i, 1);
			if (svp == NULL || *svp == NULL || !SvROK(*svp) ||
			    (bvhash = (HV *)SvRV(*svp)) == NULL ||
			    SvTYPE((SV *)bvhash) != SVt_PVHV)
				croak("Entry provided as part of bufvec was wrong!");
			if ((svp = hv_fetch(bvhash, "size",  4, 0)) != NULL)
				src->buf[i].size = SvIV(*svp);
			if ((svp = hv_fetch(bvhash, "flags", 5, 0)) != NULL)
				src->buf[i].flags = SvIV(*svp);
			if (src->buf[i].flags & FUSE_BUF_IS_FD) {
				if ((svp = hv_fetch(bvhash, "fd",    2, 0)) != NULL)
					src->buf[i].fd = SvIV(*svp);
				else
					croak("FUSE_BUF_IS_FD passed but no fd!");

				if (src->buf[i].flags & FUSE_BUF_FD_SEEK) {
					if ((svp = hv_fetch(bvhash, "pos",   3, 0)) != NULL)
						src->buf[i].fd = SvIV(*svp);
					else
						croak("FUSE_BUF_FD_SEEK passed but no pos!");
				}
			}
			else {
				if ((svp = hv_fetch(bvhash, "mem",   3, 0)) != NULL) {
					src->buf[i].mem = SvPV_nolen(*svp);
					/* Should keep Perl from free()ing the memory
					 * zone the SV points to, since it'll be
					 * free()'d elsewhere at (potentially) any
					 * time... */
					SvLEN_set(*svp, 0);
				}
			}
		}
		*bufp = src;
	}

READ_BUF_FAIL:
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("read_buf end: %i\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}

int _PLfuse_flock (const char *file, struct fuse_file_info *fi, int op) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("flock begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(fi->lock_owner)));
#else
	if (asprintf(&temp, "%llu", fi->lock_owner) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
#endif
	XPUSHs(sv_2mortal(newSViv(op)));

	PUTBACK;
	rv = call_sv(context->callback[43],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);

	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("flock end: %i\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}

#if FUSE_FOUND_MICRO_VER >= 1
int _PLfuse_fallocate (const char *file, int mode, off_t offset, off_t length,
                       struct fuse_file_info *fi) {
	int rv;
#ifndef PERL_HAS_64BITINT
	char *temp;
#endif
	FUSE_CONTEXT_PRE;
	DEBUGf("fallocate begin\n");
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(file ? sv_2mortal(newSVpv(file,0)) : &PL_sv_undef);
	XPUSHs(FH_GETHANDLE(context,fi));
	XPUSHs(sv_2mortal(newSViv(mode)));
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(offset)));
#else
	if (asprintf(&temp, "%llu", offset) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
#endif
#ifdef PERL_HAS_64BITINT
	XPUSHs(sv_2mortal(newSViv(length)));
#else
	if (asprintf(&temp, "%llu", length) == -1)
		croak("Memory allocation failure!");
	XPUSHs(sv_2mortal(newSVpv(temp, 0)));
#endif

	PUTBACK;
	rv = call_sv(context->callback[44],G_SCALAR);
	SPAGAIN;
	rv = (rv ? POPi : 0);

	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("fallocate end: %i\n", rv);
	FUSE_CONTEXT_POST;
	return rv;
}
#endif /* FUSE_FOUND_MICRO_VER >= 1 */
#endif /* FUSE_VERSION >= 29 */

struct fuse_operations _available_ops = {
.getattr		= _PLfuse_getattr,
.readlink		= _PLfuse_readlink,
.getdir			= _PLfuse_getdir,
.mknod			= _PLfuse_mknod,
.mkdir			= _PLfuse_mkdir,
.unlink			= _PLfuse_unlink,
.rmdir			= _PLfuse_rmdir,
.symlink		= _PLfuse_symlink,
.rename			= _PLfuse_rename,
.link			= _PLfuse_link,
.chmod			= _PLfuse_chmod,
.chown			= _PLfuse_chown,
.truncate		= _PLfuse_truncate,
.utime			= _PLfuse_utime,
.open			= _PLfuse_open,
.read			= _PLfuse_read,
.write			= _PLfuse_write,
.statfs			= _PLfuse_statfs,
.flush			= _PLfuse_flush,
.release		= _PLfuse_release,
.fsync			= _PLfuse_fsync,
.setxattr		= _PLfuse_setxattr,
.getxattr		= _PLfuse_getxattr,
.listxattr		= _PLfuse_listxattr,
.removexattr		= _PLfuse_removexattr,
.opendir		= _PLfuse_opendir, 
.readdir		= _PLfuse_readdir,
.releasedir		= _PLfuse_releasedir,
.fsyncdir		= _PLfuse_fsyncdir,
.init			= _PLfuse_init,
.destroy		= _PLfuse_destroy,
.access			= _PLfuse_access,
.create			= _PLfuse_create,
.ftruncate		= _PLfuse_ftruncate,
.fgetattr		= _PLfuse_fgetattr,
.lock			= _PLfuse_lock,
.utimens		= _PLfuse_utimens,
.bmap			= _PLfuse_bmap,
#if FUSE_VERSION >= 28
.ioctl			= _PLfuse_ioctl,
.poll			= _PLfuse_poll,
#endif /* FUSE_VERSION >= 28 */
#if FUSE_VERSION >= 29
.write_buf		= _PLfuse_write_buf,
.read_buf		= _PLfuse_read_buf,
.flock			= _PLfuse_flock,
#if FUSE_FOUND_MICRO_VER >= 1
.fallocate		= _PLfuse_fallocate,
#endif /* FUSE_FOUND_MICRO_VER >= 1 */
#endif /* FUSE_VERSION >= 29 */
};

MODULE = Fuse		PACKAGE = Fuse
PROTOTYPES: DISABLE

BOOT:
	MY_CXT_INIT;
#ifdef USE_ITHREADS
	MY_CXT.self = aTHX;
	MY_CXT.fuse_contexts = newHV();
#endif

void
CLONE(...)
	PREINIT:
#ifdef USE_ITHREADS
		int i;
		dTHX;
#endif
	CODE:
		PERL_UNUSED_VAR(items);
#ifdef USE_ITHREADS
		MY_CXT_CLONE;
		tTHX parent = MY_CXT.self;
		MY_CXT.self = my_perl;
#if (PERL_VERSION < 10) || (PERL_VERSION == 10 && PERL_SUBVERSION <= 0)
		/* CLONE entered without a pointer table, so we can't safely clone static data */
		if(!PL_ptr_table) {
			for(i=0;i<N_CALLBACKS;i++) {
				context->callback[i] = NULL;
			}
			context->handles = newHV();
		} else
#endif
		{
			CLONE_PARAMS *clone_param;
#if (PERL_VERSION > 13) || (PERL_VERSION == 13 && PERL_SUBVERSION >= 2)
			clone_param = Perl_clone_params_new(parent, aTHX);
#else
			CLONE_PARAMS raw_param;
			raw_param.flags = 0;
			raw_param.proto_perl = parent;
			raw_param.stashes = (AV*)sv_2mortal((SV*)newAV());
			clone_param = &raw_param;
#endif
			HV *new_contexts = newHV();

			hv_iterinit(MY_CXT.fuse_contexts);
			SV *contextsv;
			char *key;
			I32 len;
			while ((contextsv = hv_iternextsv(MY_CXT.fuse_contexts, &key, &len)) != NULL) {
				Fuse_Context context;

				if (sv_derived_from(contextsv, "Fuse::Context")) {
					IV tmp = SvIV((SV*)SvRV(contextsv));
					context = INT2PTR(Fuse_Context, tmp);
				}
				else
					croak("context is not of type Fuse::Context");

				Fuse_Context new_context = malloc(sizeof *new_context);
				struct fuse_operations *fops = malloc(sizeof (struct fuse_operations));

				if (new_context == NULL)
					croak("out of memory");
				memcpy(new_context, context, sizeof *new_context);
				memcpy(fops, context->fops, sizeof *fops);

				new_context->mountpoint = strdup(context->mountpoint);
				new_context->fops = fops;

				new_context->private_data = sv_dup_inc(context->private_data, clone_param);
				for(i=0;i<N_CALLBACKS;i++) {
					new_context->callback[i] = sv_dup_inc(context->callback[i], clone_param);
				}
				new_context->handles = SvREFCNT_inc(sv_dup(context->handles, clone_param));
				new_context->creator = my_perl;
				hv_store(new_contexts, key, len, sv_setref_pv(newSViv(0), "Fuse::Context", new_context), 0);
			}

			MY_CXT.fuse_contexts = new_contexts;
#if (PERL_VERSION > 13) || (PERL_VERSION == 13 && PERL_SUBVERSION >= 2)
			Perl_clone_params_del(clone_param);
#endif
                }
#endif

SV*
fuse_get_context()
	PREINIT:
	dTHX;
	dMY_CXT;
	struct fuse_context *fc;
	Fuse_Context context;
	CODE:
	fc = fuse_get_context();
	context = find_fuse_context(aTHX_ aMY_CXT_ fc->private_data);
	if(fc) {
		HV *hash = newHV();
		(void) hv_store(hash, "uid",   3, newSViv(fc->uid), 0);
		(void) hv_store(hash, "gid",   3, newSViv(fc->gid), 0);
		(void) hv_store(hash, "pid",   3, newSViv(fc->pid), 0);
		if (context->private_data)
			(void) hv_store(hash, "private", 7, context->private_data, 0);
#if FUSE_VERSION >= 28
		(void) hv_store(hash, "umask", 5, newSViv(fc->umask), 0);
#endif /* FUSE_VERSION >= 28 */
		RETVAL = newRV_noinc((SV*)hash);
	} else {
		XSRETURN_UNDEF;
	}
	OUTPUT:
	RETVAL

void
fuse_version()
	PPCODE:
	int gimme = GIMME_V;
	if (gimme == G_SCALAR)
		XPUSHs(sv_2mortal(newSVpvf("%d.%d", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION)));
	else if (gimme == G_ARRAY) {
#ifdef FUSE_FOUND_MICRO_VER
		XPUSHs(sv_2mortal(newSViv(FUSE_FOUND_MAJOR_VER)));
		XPUSHs(sv_2mortal(newSViv(FUSE_FOUND_MINOR_VER)));
		XPUSHs(sv_2mortal(newSViv(FUSE_FOUND_MICRO_VER)));
#else
		XPUSHs(sv_2mortal(newSViv(FUSE_MAJOR_VERSION)));
		XPUSHs(sv_2mortal(newSViv(FUSE_MINOR_VERSION)));
		XPUSHs(sv_2mortal(newSViv(0)));
#endif
	}

SV *
XATTR_CREATE()
	CODE:
	RETVAL = newSViv(XATTR_CREATE);
	OUTPUT:
	RETVAL

SV *
XATTR_REPLACE()
	CODE:
	RETVAL = newSViv(XATTR_REPLACE);
	OUTPUT:
	RETVAL

#if FUSE_VERSION >= 29

#ifdef __linux__

SV *
UTIME_NOW()
	CODE:
	RETVAL = newSViv(UTIME_NOW);
	OUTPUT:
	RETVAL

SV *
UTIME_OMIT()
	CODE:
	RETVAL = newSViv(UTIME_OMIT);
	OUTPUT:
	RETVAL

#endif /* defined(__linux__) */

SV *
FUSE_BUF_IS_FD()
	CODE:
	RETVAL = newSViv(FUSE_BUF_IS_FD);
	OUTPUT:
	RETVAL

SV *
FUSE_BUF_FD_SEEK()
	CODE:
	RETVAL = newSViv(FUSE_BUF_FD_SEEK);
	OUTPUT:
	RETVAL

SV *
FUSE_BUF_FD_RETRY()
	CODE:
	RETVAL = newSViv(FUSE_BUF_FD_RETRY);
	OUTPUT:
	RETVAL

ssize_t
fuse_buf_copy(...)
	PREINIT:
	struct fuse_bufvec *dst = NULL, *src = NULL;
	AV *av_src, *av_dst;
	HV *hv;
	SV **svp, *sv;
	int i;
	INIT:
	if (items != 2) {
		fprintf(stderr, "fuse_buf_copy needs dst and src\n");
		XSRETURN_UNDEF;
	}
	CODE:
	sv = ST(0);
	if (!(SvROK(sv) && SvTYPE(av_dst = (AV *)SvRV(sv)) == SVt_PVAV))
		croak("Argument supplied was not arrayref!");
	sv = ST(1);
	if (!(SvROK(sv) && SvTYPE(av_src = (AV *)SvRV(sv)) == SVt_PVAV))
		croak("Argument supplied was not arrayref!");

	dst = malloc(sizeof(struct fuse_bufvec) +
	    (av_len(av_dst) * sizeof(struct fuse_buf)));
	if (dst == NULL)
		croak("Memory allocation failure!");
	*dst = FUSE_BUFVEC_INIT(0);
	dst->count = av_len(av_dst) + 1;
	for (i = 0; i <= av_len(av_dst); i++) {
		svp = av_fetch(av_dst, i, 1);
		if (svp == NULL || *svp == NULL || !SvROK(*svp) ||
		    (hv = (HV *)SvRV(*svp)) == NULL ||
		    SvTYPE((SV *)hv) != SVt_PVHV)
			croak("Entry provided as part of bufvec was wrong!");
		if ((svp = hv_fetch(hv, "size",  4, 0)) != NULL)
			dst->buf[i].size = SvIV(*svp);
		if ((svp = hv_fetch(hv, "flags", 5, 0)) != NULL)
			dst->buf[i].flags = SvIV(*svp);
		if (dst->buf[i].flags & FUSE_BUF_IS_FD) {
			if ((svp = hv_fetch(hv, "fd",    2, 0)) != NULL)
				dst->buf[i].fd = SvIV(*svp);
			else
				croak("FUSE_BUF_IS_FD passed but no fd!");
		
			if (dst->buf[i].flags & FUSE_BUF_FD_SEEK) {
				if ((svp = hv_fetch(hv, "pos",   3, 0)) != NULL)
					dst->buf[i].fd = SvIV(*svp);
				else
					croak("FUSE_BUF_FD_SEEK passed but no pos!");
			}
		}
		else {
			if ((svp = hv_fetch(hv, "mem",   3, 0)) != NULL) {
				if ((dst->buf[i].mem = malloc(dst->buf[i].size)) == NULL)
					croak("Memory allocation failure!");
			}
		}
	}

	src = malloc(sizeof(struct fuse_bufvec) +
	    (av_len(av_src) * sizeof(struct fuse_buf)));
	if (src == NULL)
		croak("Memory allocation failure!");
	*src = FUSE_BUFVEC_INIT(0);
	src->count = av_len(av_src) + 1;
	for (i = 0; i <= av_len(av_src); i++) {
		svp = av_fetch(av_src, i, 1);
		if (svp == NULL || *svp == NULL || !SvROK(*svp) ||
		    (hv = (HV *)SvRV(*svp)) == NULL ||
		    SvTYPE((SV *)hv) != SVt_PVHV)
			croak("Entry provided as part of bufvec was wrong!");
		if ((svp = hv_fetch(hv, "size",  4, 0)) != NULL)
			src->buf[i].size = SvIV(*svp);
		if ((svp = hv_fetch(hv, "flags", 5, 0)) != NULL)
			src->buf[i].flags = SvIV(*svp);
		if (src->buf[i].flags & FUSE_BUF_IS_FD) {
			if ((svp = hv_fetch(hv, "fd",    2, 0)) != NULL)
				src->buf[i].fd = SvIV(*svp);
			else
				croak("FUSE_BUF_IS_FD passed but no fd!");
		
			if (src->buf[i].flags & FUSE_BUF_FD_SEEK) {
				if ((svp = hv_fetch(hv, "pos",   3, 0)) != NULL)
					src->buf[i].fd = SvIV(*svp);
				else
					croak("FUSE_BUF_FD_SEEK passed but no pos!");
			}
		}
		else {
			if ((svp = hv_fetch(hv, "mem",   3, 0)) != NULL) {
				src->buf[i].mem = SvPV_nolen(*svp);
				SvLEN_set(*svp, 0);
			}
		}
	}
	RETVAL = fuse_buf_copy(dst, src, 0);
	if (RETVAL > 0) {
		for (i = 0; i < dst->count; i++) {
			svp = av_fetch(av_dst, i, 1);
			if (svp == NULL || *svp == NULL || !SvROK(*svp) ||
			    (hv = (HV *)SvRV(*svp)) == NULL ||
			    SvTYPE((SV *)hv) != SVt_PVHV)
				croak("Entry provided as part of bufvec was wrong!");
			if (!(dst->buf[i].flags & FUSE_BUF_IS_FD)) {
#if (PERL_VERSION < 8) || (PERL_VERSION == 8 && PERL_SUBVERSION < 9)
				sv = newSV(0);
				sv_upgrade(sv, SVt_PV);
#else
				sv = newSV_type(SVt_PV);
#endif
				SvPV_set(sv, (char *)dst->buf[i].mem);
				SvLEN_set(sv, dst->buf[i].size);
				SvCUR_set(sv, dst->buf[i].size);
				SvPOK_on(sv);
				SvREADONLY_on(sv);
				(void) hv_store(hv, "mem",   3, sv, 0);
			}
		}
	}
	free(dst);
	free(src);
	OUTPUT:
	RETVAL

#endif /* FUSE_VERSION >= 29 */

void
perl_fuse_setup(...)
	PREINIT:
	struct fuse_operations *fops = malloc(sizeof (struct fuse_operations));
	int i, debug;
	char *mountpoint;
	char *mountopts;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse *fuse;
	Fuse_Context context= malloc(sizeof *context);
	struct fuse_chan *fc;
	dMY_CXT;
	INIT:
	if(items != N_CALLBACKS + N_FLAGS) {
		fprintf(stderr,"Perl<->C inconsistency or internal error\n");
		XSRETURN_UNDEF;
	}
	memset(fops, 0, sizeof(struct fuse_operations));
	memset(context, 0, sizeof *context);
	PPCODE:
	if (context == NULL || fops == NULL)
		croak("out of memory");
	debug = SvIV(ST(0));
	context->threaded = SvIV(ST(1));
	context->handles = (HV*)(sv_2mortal((SV*)(newHV())));
        SvREFCNT_inc(context->handles);
        context->creator = my_perl;
	if(context->threaded) {
#ifdef FUSE_USE_ITHREADS
		SvSHARE((SV*)(context->handles));
#else
		fprintf(stderr,"FUSE warning: Your script has requested multithreaded "
		               "mode, but your perl was not built with a supported "
		               "thread model. Threads are disabled.\n");
		context->threaded = 0;
#endif
	}
	mountpoint = SvPV_nolen(ST(2));
	mountopts = SvPV_nolen(ST(3));
#if FUSE_VERSION >= 28
	fops->flag_nullpath_ok = SvIV(ST(4));
#endif /* FUSE_VERSION >= 28 */
	context->utimens_as_array = SvIV(ST(5));
#if FUSE_VERSION >= 29
	fops->flag_nopath = SvIV(ST(6));
	fops->flag_utime_omit_ok = SvIV(ST(7));
#endif /* FUSE_VERSION >= 29 */
	for(i=0;i<N_CALLBACKS;i++) {
		SV *var = ST(i+N_FLAGS);
		/* allow symbolic references, or real code references. */
		if(SvOK(var) && (SvPOK(var) || (SvROK(var) && SvTYPE(SvRV(var)) == SVt_PVCV))) {
			void **tmp1 = (void**)&_available_ops, **tmp2 = (void**)fops;
			/* Dirty hack, to keep anything from overwriting the
			 * flag area with a pointer. There should never be
			 * anything passed as 'junk', but this prevents
			 * someone from doing it and screwing things up... */
			if (i == 38)
				continue;
			tmp2[i] = tmp1[i];
			/* it is important to protect these values until shutdown */
			context->callback[i] = SvREFCNT_inc(var);
		} else if(SvOK(var)) {
			croak("invalid callback (%i) passed to perl_fuse_setup "
			      "(%s is not a string, code ref, or undef).\n",
			      i+N_FLAGS,SvPVbyte_nolen(var));
		} else {
			context->callback[i] = NULL;
		}
	}
	/*
	 * XXX: What comes here is just a ridiculous use of the option parsing API
	 * to hack on compatibility with other parts of the new API. First and
	 * foremost, real C argc/argv would be good to get at...
	 */
	if ((mountopts || debug) && fuse_opt_add_arg(&args, "") == -1) {
		fuse_opt_free_args(&args);
		croak("out of memory\n");
	}
	if (mountopts && strcmp("", mountopts) &&
	     (fuse_opt_add_arg(&args, "-o") == -1 ||
	     fuse_opt_add_arg(&args, mountopts) == -1)) {
		fuse_opt_free_args(&args);
		croak("out of memory\n");
	}
	if (debug && fuse_opt_add_arg(&args, "-d") == -1) {
		fuse_opt_free_args(&args);
		croak("out of memory\n");
	}
	fc = fuse_mount(mountpoint,&args);
	if (fc == NULL)
		croak("could not mount fuse filesystem!\n");
	context->mountpoint = strdup(mountpoint);
	fuse = fuse_new(fc,&args,fops,sizeof(*fops),context->mountpoint);
	fuse_opt_free_args(&args);
	context->fuse = fuse;
	context->fops = fops;
	context->se = fuse_get_session(fuse);
	context->ch = fuse_session_next_chan(context->se, NULL);
	context->bufsize = fuse_chan_bufsize(context->ch);
	hv_store(MY_CXT.fuse_contexts, mountpoint, strlen(mountpoint),
		 sv_setref_pv(newSViv(0), "Fuse::Context", context), 0);
	XPUSHs(newSVpv(mountpoint, strlen(mountpoint)));
	XPUSHs(sv_2mortal(newSViv(fuse_chan_fd(fc))));

int
perl_fuse_session_exited(const char *mountpoint)
CODE:
	dMY_CXT;
	Fuse_Context context = find_fuse_context(aTHX_ aMY_CXT_ mountpoint);
	if (!context)
		croak("no such session");
	RETVAL = fuse_session_exited(context->se);
OUTPUT:
	RETVAL

int
perl_fuse_process_buf(const char *mountpoint, SV *sv, Fuse_Channel tmpch)
CODE:
	dMY_CXT;
	Fuse_Context context = find_fuse_context(aTHX_ aMY_CXT_ mountpoint);
	STRLEN len;
	void *mem = SvPV(sv, len);

	if (!context)
		croak("no such session");

	fuse_session_process(context->se, mem, len, tmpch);

	RETVAL = 0;
OUTPUT:
	RETVAL

void
perl_fuse_receive_buf(const char *mountpoint)
PPCODE:
	dMY_CXT;
	Fuse_Context context = find_fuse_context(aTHX_ aMY_CXT_ mountpoint);
	int res;
	void *buf = malloc(context->bufsize);
	struct fuse_chan *tmpch = context->ch;
	SV *ret;
	if (buf == NULL) {
		XSRETURN_UNDEF;
	}

	do {
		res = fuse_chan_recv(&tmpch, buf, context->bufsize);
	} while (res == -EINTR);

	if (res <= 0) {
		free(buf);
		XSRETURN_UNDEF;
	}

	ret = newSVpv(buf, res);
	free(buf);
	XPUSHs(sv_2mortal(ret));
	XPUSHs(sv_setref_pv(sv_newmortal(), "Fuse::Channel", tmpch));

void
perl_fuse_shutdown(const char *mountpoint)
CODE:
	dMY_CXT;
	Fuse_Context context = find_fuse_context(aTHX_ aMY_CXT_ mountpoint);
	fuse_unmount(context->mountpoint, context->ch);
	fuse_destroy(context->fuse);
        hv_delete(MY_CXT.fuse_contexts, context->mountpoint, strlen(context->mountpoint), 0);

#if FUSE_VERSION >= 28

void
pollhandle_destroy(...)
    PREINIT:
	struct fuse_pollhandle *ph;
    INIT:
	if (items != 1) {
		fprintf(stderr, "No pollhandle passed?\n");
		XSRETURN_UNDEF;
	}
    CODE:
	ph = INT2PTR(struct fuse_pollhandle*, SvIV(ST(0)));
	fuse_pollhandle_destroy(ph);

int 
notify_poll(...)
    PREINIT:
	struct fuse_pollhandle *ph;
    INIT:
	if (items != 1) {
		fprintf(stderr, "No pollhandle passed?\n");
		XSRETURN_UNDEF;
	}
    CODE:
	ph = INT2PTR(struct fuse_pollhandle*, SvIV(ST(0)));
	RETVAL = fuse_notify_poll(ph);
    OUTPUT:
	RETVAL

#endif

MODULE = Fuse		PACKAGE = Fuse::Context	PREFIX = perl_fuse_context_
void
perl_fuse_context_DESTROY(Fuse_Context context)
PREINIT:
	int i;
	dTHX;
CODE:
        if (aTHX != context->creator)
		return;

	for(i = 0 ; i < N_CALLBACKS ; i++) {
	    SV *var = context->callback[i];
	    if(var)
		SvREFCNT_dec(var);
	}
	SvREFCNT_dec((SV *)context->handles);
	SvREFCNT_dec(context->private_data);
	free(context->fops);
	free(context->mountpoint);
	free(context);

