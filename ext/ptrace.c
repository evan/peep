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

static VALUE p_module;
static VALUE p_error;

static VALUE sizes () {
  VALUE p_hash = rb_hash_new();

  unsigned short s = 0x0001;
  rb_hash_aset(p_hash, rb_str_new2("little_endian"), ((*(unsigned char*)&s) ? Qtrue : Qfalse));    
  rb_hash_aset(p_hash, rb_str_new2("address"), INT2NUM(sizeof(void *)));
  rb_hash_aset(p_hash, rb_str_new2("time_t"), INT2NUM(sizeof(time_t)));
  rb_hash_aset(p_hash, rb_str_new2("double"), INT2NUM(sizeof(double)));
  rb_hash_freeze(p_hash);
  return p_hash;
}

static VALUE item_offsets () {
  VALUE p_hash = rb_hash_new();
  
#define OFFSET_(EL) rb_hash_aset(p_hash, rb_str_new2(#EL), INT2NUM(offsetof(struct _stritem, EL)))  
  OFFSET_(h_next);
  OFFSET_(nbytes);
  OFFSET_(time);
  OFFSET_(exptime);
  OFFSET_(refcount);
  OFFSET_(nsuffix);
  OFFSET_(nkey);
  OFFSET_(it_flags);
  OFFSET_(slabs_clsid);
  OFFSET_(end);  
  
  rb_hash_freeze(p_hash);
  return p_hash;
}

static VALUE stats_offsets () {
  VALUE p_hash = rb_hash_new();
  
#define STATS_(EL) rb_hash_aset(p_hash, rb_str_new2(#EL), INT2NUM(offsetof(struct stats, EL)))
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
  
  rb_hash_freeze(p_hash);
  return p_hash;
}

static VALUE settings_offsets () {
  VALUE p_hash = rb_hash_new();
  
#define SETTINGS_(EL) rb_hash_aset(p_hash, rb_str_new2(#EL), INT2NUM(offsetof(struct settings, EL)))
  SETTINGS_(maxbytes);
  SETTINGS_(maxconns);
  SETTINGS_(port);
  SETTINGS_(udpport);  
  // SETTINGS_(inter);  
  SETTINGS_(verbose);  
  SETTINGS_(oldest_live);  
  SETTINGS_(managed);
  SETTINGS_(evict_to_free);
  // SETTINGS_(socketpath);
  SETTINGS_(access);
  SETTINGS_(factor);
  SETTINGS_(chunk_size);
  SETTINGS_(num_threads);  
  SETTINGS_(prefix_delimiter);
  SETTINGS_(detail_enabled);  
  
  rb_hash_freeze(p_hash);
  return p_hash;
}

static void fail(int pid) {
  char buffer[16];
  sprintf(buffer, "%d", pid);
  rb_sys_fail(buffer);  
}

static VALUE attach (VALUE self, VALUE pid_)
{
  pid_t pid = NUM2INT(pid_);
  if (ptrace (PTRACE_ATTACH, pid, 0, 0))
    fail(pid);
  return Qtrue;
} 

static VALUE detach (VALUE self, VALUE pid_)
{
  pid_t pid = NUM2INT(pid_);
  if (ptrace (PTRACE_DETACH, pid, 0, 0))
    fail(pid);
  return Qtrue;
}

static VALUE peek (VALUE self, VALUE pid_, VALUE address)
{
  pid_t pid = NUM2INT(pid_);
  long byte = ptrace (PTRACE_PEEKDATA, pid, (void *) NUM2ULONG(address), 0);
  if (byte == -1 && errno)
    fail(pid);
  return ULONG2NUM((unsigned long) byte);
}

void
Init_ptrace (void)
{
  p_module = rb_define_module ("Peep");

  rb_define_const(p_module, "SIZES", sizes());
  rb_define_const(p_module, "ITEM_OFFSETS", item_offsets());
  rb_define_const(p_module, "STATS_OFFSETS", stats_offsets());
  rb_define_const(p_module, "SETTINGS_OFFSETS", settings_offsets());

  rb_define_module_function (p_module, "attach", attach, 1);
  rb_define_module_function (p_module, "detach", detach, 1);
  rb_define_module_function (p_module, "peek", peek, 2);
}
