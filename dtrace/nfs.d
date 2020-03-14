#!/usr/sbin/dtrace -s

/*
 * A Dtrace tool to watch all NFS-related activity in a running FreeBSD kernel
 *
 * Author: Peter Eriksson <pen@lysator.liu.se>
 */

#pragma D option dynvarsize=20m

fbt::nfsvno_namei:entry {
  self->ts_namei = timestamp;
  
  self->namei_uid   = args[1]->ni_cnd.cn_cred->cr_uid;
  self->namei_op    = args[1]->ni_cnd.cn_nameiop;
  self->namei_pnbuf = stringof(args[1]->ni_cnd.cn_pnbuf);
}

fbt::nfsvno_namei:return {
  dt = timestamp - self->ts_namei;
  
  printf("%10d µs : %Y : %a : uid=%d, op=%lu, path=%s",
    dt/1000,
    walltimestamp,
    caller,
    self->namei_uid,
    self->namei_op,
    self->namei_pnbuf);

  self->namei_uid = 0;
  self->namei_op = 0;
  self->namei_pnbuf = 0;
  self->ts_namei;
}


fbt::nfsrvd_dorpc:entry {
  self->dorpc_uid = args[0]->nd_cred->cr_uid;
  self->ts_dorpc = timestamp;
}

fbt::nfsrvd_dorpc:return {
  dt = timestamp - self->ts_dorpc;
  printf("%10d µs : %Y : %a : uid=%d",
    dt/1000,
    walltimestamp,
    caller,
    self->dorpc_uid);
  self->ts_dorpc = 0;
  self->dorpc_uid = 0;
}


fbt::nfsv4_lock:entry {
  self->lp = (struct nfsv4lock *) arg0;
  self->ts_lock = timestamp;
}

fbt::nfsv4_lock:return {
  dt = timestamp - self->ts_lock;

  printf("%10d µs : %Y : %a : ret=%d, lock=%d, usecnt=%d",
    dt/1000,
    walltimestamp,
    caller,
    arg1,
    self->lp->nfslock_lock,
    self->lp->nfslock_usecnt);
    
  self->ts_lock = 0;
  self->ts_unlock = timestamp;
}


fbt::nfsv4_unlock:return {
  dt = timestamp - self->ts_unlock;
  
  printf("%10d µs : %Y : %a : ret=%d, lock=%d, usecnt=%d",
    dt/1000,
    walltimestamp,
    caller,
    arg1,
    self->lp->nfslock_lock,
    self->lp->nfslock_usecnt);
    
  self->lp = 0;	
  self->ts_unlock = 0;
}


fbt::nfsrv_getuser:entry {
  self->ts_getuser = timestamp;
  self->getuser_type = arg0;
  self->getuser_uid = arg1;
  self->getuser_gid = arg2;
}

fbt::nfsrv_getuser:return {
  dt = timestamp - self->ts_getuser;
  
  printf("%10d µs : %Y : %a : type=%d, uid=%d, gid=%d",
    dt/1000,
    walltimestamp,
    caller,
    self->getuser_type,
    self->getuser_uid,
    self->getuser_gid);
    
 self->ts_getuser = 0;
 self->ts_getuser_type = 0;
 self->ts_getuser_uid = 0;
 self->ts_getuser_gid = 0;
}



/*
  0  44963              newnfs_timer:return          3 µs : 2020 Mar 14 15:58:24 : kernel`softclock_call_cc+0x14f
  0  51910     nfsv4_getref_nonblock:return          1 µs : 2020 Mar 14 15:58:24 : kernel`nfsrv_servertimer+0x10e
  0  37280         nfsrv_servertimer:return         17 µs : 2020 Mar 14 15:58:24 : kernel`newnfs_timer+0x39
*/


fbt::*nfs*:entry / probefunc != "nfsvno_namei"  &&
		   probefunc != "nfsrvd_dorpc"  &&
		   probefunc != "nfsv4_lock"    &&
		   probefunc != "nfsrv_getuser" &&
		   probefunc != "nfsv4_unlock"  &&
		   probefunc != "nfsv4_unlock"  &&
		   
		   probefunc != "newnfs_timer"           &&
		   probefunc != "nfsv4_getref_nonblock"  &&
		   probefunc != "nfsrv_servertimer"
		   /  {
  self->ts[probefunc] = timestamp;
}

fbt::*nfs*:return / self->ts[probefunc] / {
  dt = timestamp - self->ts[probefunc];
  
  printf("%10d µs : %Y : %a",
    dt/1000,
    walltimestamp,
    caller);
    
 self->ts[probefunc] = 0;
}
