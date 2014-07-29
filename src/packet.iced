
{pack} = require 'purepack'
{make_esc} = require 'iced-error'
C = require './const'

#===============================================================

pad = (buf, len) ->
  if (diff = (len - buf.length)) < 0
    throw new Error "Can't shrink a packet, can only pad it with 0s"
  else
    buf = Buffer.concat [ buf, (new Buffer (0 for [0...diff]))]
  buf

#===============================================================

class Packet

  #---------

  constructor : ({@stubs, @dummy, @packetno}) ->
    @_buf_cache = null
    @_hmac_cache = null
    @_offset = null

  #---------

  set_offset : (o) -> @_offset = o
  get_offset : ( ) -> @_offset

  #---------

  reset : () ->
    @_buf_cache = @_hmac_cache = null
    @dummy = false

  #---------

  to_buffer : () ->
    unless @_buf_cache = null
      obj = [ @packetno, @packet_tag(), @to_json() ]
      packed = pack obj
      if @_dummy_len? then packet = pad packed, @_dummy_len
      len = pack packed.length
      @_buf_cache = Buffer.concat [ len, packed ]
      @dummy_len = @_buf_cache.length if @dummy?
    @_buf_cache

  #---------

  compute_hmac : (cb) ->
    err = null
    unless @_hmac_cache
      await @stubs.hmac_sha256 { buf : @to_buffer() }, defer err, @_hmac_cache
    cb err, @_hmac_cache

  #---------

  get_hmac : () -> @_hmac_cache

#===============================================================

exports.IndexPacket = class IndexPacket extends Packet

  TAG : 0x2

  #---------

  constructor : ( { packetno, stubs, @data}) -> super { packetno, stubs }
  packet_tag : () -> IndexPacket.TAG
  to_json : () -> @data

  #---------

  crypto : (cb) ->
    await @compute_hmac defer err
    cb err

  #---------

  reset : ({data}) ->
    super()
    @data = data

#===============================================================

exports.DataPacket = class DataPacket extends Packet

  TAG : 0x3

  #---------

  constructor : ( {packetno, @plaintext, stubs}) ->
    super { packetno, stubs }
    @hmac = null
    @ciphertext = null

  #---------

  packet_tag : () -> DataPacket.TAG

  #---------

  crypto : (cb) ->
    esc = make_esc cb, "DataPacket.encrypt"
    await @stubs.aes256ctr_encrypt { buf : @plaintext }, esc defer @ciphertext
    await @compute_hmac esc defer()
    cb null

  #---------

  to_json : () -> @ciphertext

#===============================================================

exports.HeaderPacket = class HeaderPacket extends Packet

  TAG : 0x1

  #---------

  constructor : ( { @pgp, stubs, len}) ->
    super { stubs, packetno : 0 }
    @_dummy_len = len

  #---------

  packet_tag : () -> HeaderPacket.TAG

  #---------

  to_json : () -> [ C.magic, C.version, @pgp ]

#===============================================================

