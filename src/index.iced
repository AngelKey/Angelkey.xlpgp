
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
    @_packets = {}

  #--------

  index : ( {index, hmac } ) ->
    @_hmacs[index] = hmac

  #--------------

  get_hmac : (i) -> @_hmacs[i] or @_empty_hash

  #--------------

  gen : ({dummy, packetno}, cb) ->
    hpip = @config.hashes_per_index_packet
    data = [ packetno, (@get_hmac(i+packno) for i in [0...hpip]) ]
    pkt = new IndexPacket { data , @stubs, @dummy }
    @_packets[packetno] = pkt
    cb null

  #--------------

  generate : (args, cb) ->
    esc = make_esc cb, "HashIndex::generate"
    await @sanity_check esc defer() unless args.skip_sanity_check
    prev = null
    hpib = @config.hashes_per_block - 1
    begin = @_counts.total_blocks * hpib
    end = @_hmacs.length
    i = @_counts.interior_index_blocks # add 1 for the header block
    packets = []
    while i > 0
      index = []
      index.push [ (i+2), prev.get_hmac() ] if prev? # add 1 for header Block, and 1 for the next guy
      index.push [ begin, @_hmacs[begin...end] ]
      end = begin
      begin -= hpid
      pkt = new IndexPacket { index, @stubs }
      await pkt.compute_hmac esc defer()
      packets.push pkt
      prev = pkt
      i--
    packets.reverse()
    if args.clear
      @_hmacs = []
    else
      for p,i in packets
        @_hmacs[i+1] = p
    cb null, packets

  #------------

  do_last_packet : (cb) ->
    i = @_hmacs.length - @_counts.hashes_in_last_block
    index = [ i, @_hmacs[i...] ]
    pkt = new IndexPacket { index, @stubs }
    await pkt.compute_hmac defer err
    cb err, pkt

  #------------

  sanity_check : (cb) ->
    err = null
    if (a = (@_hmacs.length + 1)) isnt (b = @_counts.total_blocks)
      err = new Error "Wrong number of file blocks; wanted #{b} but got #{a}"
    else
      last = @_hmacs.length - 1
      for i in [0...@_counts.file_blocks]
        unless @_hmac[last-i]?
          err = new Error "Missing file block at index #{last-i}"
          break
    cb err

  #--------

  layout : (cb) ->
    esc = make_esc cb, "HashIndex::layout"
    await @stubs.get_length esc defer len
    n_blocks = Math.ceil(len / @config.blocksize)
    [q,r] = divmod (n_blocks-2), (@config.hashes_per_block-1)
    r += 2

    # the total number of hash blocks needed.  The last one will have
    # r hashes in it, and all of the others will have (hashes_per_block-1) hashes
    # and also a next pointer
    @_counts =
      file_blocks : n_blocks
      interior_index_blocks : q
      index_blocks : q + 1
      hashes_in_last_block : r
      total_blocks : n_blocks + q + 1

    cb null

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






