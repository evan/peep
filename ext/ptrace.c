#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include "ruby.h"
#include "rubyio.h"
#include "intern.h"
#include "memcached.h"
  
VALUE sizes () {
  VALUE pt_hash = rb_hash_new();

  unsigned short s = 0x0001;
  rb_hash_aset(pt_hash, rb_str_new2("little-endian"), ((*(unsigned char*)&s) ? T_TRUE : T_FALSE));  
  
#define SIZE_(EL,VAL) rb_hash_aset(pt_hash, rb_str_new2(#EL), INT2NUM(sizeof(VAL)))
  SIZE_(addr_size, void *);
  SIZE_(time_t_size, time_t);
  rb_hash_freeze(pt_hash);
  return pt_hash;
}

VALUE item_offsets () {
  VALUE pt_hash = rb_hash_new();
  
#define OFFSET_(EL) rb_hash_aset(pt_hash, rb_str_new2(#EL), INT2NUM(offsetof(struct _stritem, EL)))  
  OFFSET_(h_next);
  OFFSET_(nbytes);
  OFFSET_(time);
  OFFSET_(exptime);
  OFFSET_(refcount);
  OFFSET_(nkey);
  OFFSET_(it_flags);
  OFFSET_(slabs_clsid);
  OFFSET_(end);  
  
  rb_hash_freeze(pt_hash);
  return pt_hash;
}

VALUE stats_offsets () {
  VALUE pt_hash = rb_hash_new();
  
#define STATS_(EL) rb_hash_aset(pt_hash, rb_str_new2(#EL), INT2NUM(offsetof(struct stats, EL)))
  STATS_(curr_items);
  STATS_(total_items);
  STATS_(curr_bytes);
  STATS_(curr_conns);  
  STATS_(total_conns);  
  STATS_(conn_structs);  
  STATS_(get_cmds);
  STATS_(set_cmds);
  STATS_(get_hits);
  STATS_(get_misses);  
  STATS_(started);  
  STATS_(bytes_read);
  STATS_(bytes_written);
  
  rb_hash_freeze(pt_hash);
  return pt_hash;
}

void
Init_ptrace (void)
{
  VALUE pt_module = rb_define_pt_module ("Ptrace");
  rb_define_const(pt_module, "SIZES", sizes());
  rb_define_const(pt_module, "ITEM_OFFSETS", item_offsets());
  rb_define_const(pt_module, "STATS_OFFSETS", stats_offsets());
}
