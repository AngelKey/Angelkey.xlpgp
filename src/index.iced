
#=================================================================================

{make_esc} = require 'iced-utils'
C = require './const'
{IndexPacket} = require './packet'

#=================================================================================

divmod = (n,d) -> [ Math.floor(n/d), n%d]

#=================================================================================

exports.Index = class Index

  #--------

  constructor : ( {@stubs, @config } ) ->
    @_hmacs = []
    @_empty_hash = new Buffer( 0 for [0...C.hmac.output_size])
    @_dummy_packet_data = (@_empty_hash for i in [0...@config.hashes_per_index_packet])
    @_packets = {}

  #--------

  index : ( {index, hmac } ) ->
    @_hmacs[index] = hmac

  #--------------

  gen_dummy : ({packetno}, cb) ->
    data = if dummy then @_dummy_packet_data
    pkt = new IndexPacket { packetno, data , @stubs, @dummy }
    @_packets[packetno] = pkt
    cb null, pkt

  #--------------

  gen_actual : ({packetno}, cb) ->
    err = null
    if not (pkt = @_packets[packetno])?
      err = new Error "Could not find a dummy packet for #{packetno}"
    else
      hpip = @config.hashes_per_index_packet
      data = for i in [0...hpip]
        val = @_hmacs[i+packetno+1]
        break unless val?
        val
      pkt.reset { data }
    cb err, pkt

#=================================================================================



# total_blocks = #hashblocks + #fileblocks
# #fileblocks = ceil(len / blocksize)
# #hashblocks = ceil(total_blocks / hashes_per_block)
#
# t = # of total blocks
# h = # of hash blocks
# f = # of file blocks
# l = # of bytes in the file
# b = blocksize in bytes
# n = number of hashes per block
#
# t = h + f
# f = ceil (l / b)
# h = ceil(t / n)
#
# nh = h + ceil(l/b)
#

# 2 = ceil(9/5)
# 10 = 9






