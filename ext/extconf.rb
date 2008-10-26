
require 'mkmf'

find_header "memcached.h", dir_config("memcached").first
have_header "sys/ptrace.h" 
have_header "sys/ptrace.h" 
have_header "sys/user.h"

create_makefile "ptrace" 
