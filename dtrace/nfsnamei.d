#!/usr/sbin/dtrace -s

fbt::nfsvno_namei:entry {
  printf("%s [uid=%d]",
   stringof(args[1]->ni_cnd.cn_pnbuf),
   args[1]->ni_cnd.cn_cred->cr_uid);
}
