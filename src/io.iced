
{make_esc} = require 'iced-error'


#==============================================================================

exports.PacketWriter = class PacketWriter

  #---------------------------

  constructor : ({@stubs}) ->
    @_pos = 0

  #---------------------------

  rewind : (cb) ->
    @_pos = 0
    cb null

  #---------------------------

  write : ( { offset, packet, packets}, cb) ->
    esc = make_esc cb, "PacketWriter::write"
    packets or= [ packet ]
    start = @_index
    @_pos = offset if offset?
    start_pos = @_pos
    for p in packets
      buf = p.to_buffer()
      await @stubs.write { buf, start : @_pos }, esc defer()
      @_pos += buf.length
    cb null, start_pos

#==============================================================================

exports.BlockReader = class BlockReader

  #---------------------------

  constructor : ({@stubs, @config}) ->
    @_pos = 0

  #---------------------------

  read : (cb) ->
    await @stubs.read { start : @_pos, bytes : @config.blocksize }, defer err, buf
    unless err?
      @_pos += buf.length
    eof = not(err) and (not(buf?) or (buf.length is 0))
    cb err, buf, eof

#==============================================================================

