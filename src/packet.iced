
{mpack} = require 'purepack'
{make_esc} = require 'iced-error'

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

  constructor : ({@stubs, @dummy}) ->
    @_buf_cache = null
    @_hmac_cache = null
    @_offset = null

  #---------

  set_offset : (o) -> @_offset = o

  #---------

  reset : () -> 
    @_buf_cache = @_hmac_cache = null
    @dummy = false

  #---------

  to_buffer : () ->
    unless @_buf_cache = null
      obj = [ @packet_tag(), @to_json() ]
      packed = mpack obj
      if @_dummy_len? then packet = pad packet, @_dummy_len
      len = mpack packed.length
      @_buf_cache = Buffer.concat [ len, packed ]
      @dummy_len = @_buf_cache.length if @dummy?
    @_buf_cache

  #---------

  compte_hmac : (cb) ->
    err = null
    unless @hmac?
      await @stubs.hmac_sha256 { buf : @to_buffer() }, defer err, @hmac
    cb err, @_hmac_cache

  #---------

  get_hmac : () -> @_hmac_cache

#===============================================================

exports.IndexPacket = class IndexPacket extends Packet

  TAG : 0x2

  #---------

  constructor : ( {stubs, @index}) -> super { stubs }
  packet_tag : () -> IndexPacket.TAG
  to_json : () -> @index

#===============================================================

exports.DataPacket = class DataPacket extends Packet

  TAG : 0x3

  #---------

  constructor : ( {@plaintext, stubs}) ->
    super { stubs }
    @hmac = null
    @ciphertext = null

  #---------

  packet_tag : () -> DataPacket.TAG

  #---------

  encrypt : (cb) ->
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

  constructor : ( { @pgp, @stubs}) ->
    super { stubs }

  #---------

  packet_tag : () -> HeaderPacket.TAG

  #---------

  to_json : () -> @pgp

#===============================================================

