#!/usr/sbin/dtrace -s

/*
 * A Dtrace tool to watch all ZFS-related activity in a running FreeBSD kernel
 *
 * Author: Peter Eriksson <pen@lysator.liu.se>
 */

#pragma D option dynvarsize=20m


fbt::*zfs*:entry {
  self->ts[probefunc] = timestamp;
}

fbt::*zfs*:return / self->ts[probefunc] /  {
  dt = timestamp - self->ts[probefunc];
  
  printf("%10d µs : %Y : %a",
    dt/1000,
    walltimestamp,
    caller);
    
 self->ts[probefunc] = 0;
}
