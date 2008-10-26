
$LOAD_PATH << "/home/eweaver/p/fauna/peep/ext"
require 'ptrace'

module Peep

  class Analysis
    attr_reader :pid
    attr_reader :addresses
    attr_reader :pack_format

    def read_long(addr)
      Peep.peek(pid, addr)
    end

    def read_int(addr)
      n = Peep.peek(pid, addr)
      SIZES['little_endian'] ? n & 0xffffffff : (n >> 32) & 0xffffffff
    end

    def read_uint8(addr)
      offset = addr % SIZES['address']
      word = read_long(addr - offset)
      [word].pack(pack_format)[offset]
    end

    def read_bytes(addr, nbytes)
      buffer = ""
      (nbytes / SIZES['address'].to_f).ceil.times do |offset|
        buffer << [read_long(addr + offset * SIZES['address'])].pack(pack_format)
      end
      buffer[0, nbytes]
    end
    
    def read_double(addr)
      read_bytes(addr, SIZES['double']).unpack('d')
    end

    def init_addresses
      @addresses = {}
      IO.popen("gdb -q memcached #{pid}", "w+") do |gdb|
        %w(primary_hashtable hash_items hashpower stats settings).each do | key|
          gdb.puts "p &#{key}"
          1 while (line = gdb.gets) !~ /\(gdb\)/
          @addresses[key] = line.split.last.hex
        end
        gdb.puts "detach"
        gdb.puts "quit"
      end
    end

    def initialize(pid, options = {})
      raise TypeError unless pid.is_a? Integer
      @pack_format = SIZES['address'] == 4 ? "l" : "q"
      @pid = pid
      init_addresses
    end

    def attached
      GC.disable
      Peep.attach pid
      sleep 0.5
      value = yield
      Peep.detach pid
      GC.enable
      value
    ensure
      Process.kill("CONT", pid)
    end

    def basics
      @basics ||= attached do
        {
          'hashtable' => read_long(addresses['primary_hashtable']),
          'hash_items' => read_long(addresses['hash_items']),
          'hashpower' => read_int(addresses['hashpower'])
        }
      end
    end

    def stats
      @stats ||= attached do
        # Static
        Hash[*
          STATS_OFFSETS.map do |key, offset|
            [key, read_long(addresses['stats'] + offset)]
          end.flatten
        ]
      end
    end

    def settings
      @settings ||= attached do
        # Static
        Hash[*
          SETTINGS_OFFSETS.map do |key, offset|
            [key, case key
                when 'prefix_delimiter'
                  read_int(addresses['settings'] + offset).chr
                when 'factor'
                  read_double(addresses['settings'] + offset)
                else
                  read_long(addresses['settings'] + offset)
             end]
          end.flatten
        ]
      end
    end

    IT_FLAGS = {
      1 => "L",
      2 => "D",
      4 => "S"
    }

    HEADER = ['time', 'exptime', 'nbytes', 'nsuffix', 'it_flags', 'slabs_clsid', 'nkey', 'key', 'expired', 'flushed']

    def items
      basics

      now = Time.now.to_i - stats['started']
      flushed = settings['oldest_live']
      items = []

      attached do
        (2**basics['hashpower']).times do |i|
          bucket = read_long(basics['hashtable'] + i * SIZES['address'])

          while !bucket.zero?
            item = [
              time = read_int(bucket + ITEM_OFFSETS['time']),
              exptime = read_int(bucket + ITEM_OFFSETS['exptime']),
              read_int(bucket + ITEM_OFFSETS['nbytes']),
              read_uint8(bucket + ITEM_OFFSETS['nsuffix']),
              IT_FLAGS[read_uint8(bucket + ITEM_OFFSETS['it_flags'])],
              read_uint8(bucket + ITEM_OFFSETS['slabs_clsid']),
              nkey = read_uint8(bucket + ITEM_OFFSETS['nkey']),
              read_bytes(bucket + ITEM_OFFSETS['end'], nkey),

              !(exptime.zero? or now < exptime), # expired?
              !(flushed.zero? or flushed < time) # flushed?
            ]
            
            block_given? ? yield(*item) : items << item

            bucket = read_long(bucket + ITEM_OFFSETS['h_next'])
          end
        end
      end

      items unless block_given?
    end

  end
end
