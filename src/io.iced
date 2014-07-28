
{make_esc} = require 'iced-error'


#==============================================================================

exports.PacketWriter = class PacketWriter

  #---------------------------

  constructor : ({@stubs}) ->
    @_pos = 0
    @_index = 0

  #---------------------------

  rewind : () ->
    @_pos = 0
    @_index = 0

  #---------------------------

  write : ( { packet, packets}, cb) ->
    esc = make_esc cb, "PacketWriter::write"
    packets or= [ packet ]
    start = @_index
    for p in packets
      buf = p.to_buffer()
      await @stubs.write { buf, start : @_pos }, esc defer()
      @_pos += buf.length
      @_index++
    cb null, start

#==============================================================================

