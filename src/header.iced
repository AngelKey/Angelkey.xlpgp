
C = require './const'
{pack} = require 'purepack'
{make_esc} = require 'iced-error'
{HeaderPacket} = require './packet'

#===============================================================

exports.Header = class Header

  #-------------

  constructor : ( {@stubs, @keys, @hmac_packet_1 }) ->
    @_encrypted = null

  #-------------

  generate : (cb) ->
    json = [ C.version, @keys.cipher.key, @keys.cipher.iv, @keys.hmac.key, @hmac_packet_1 ]
    buf = pack json
    await @stubs.encrypt_pgp_header { buf }, defer err, @_encrypted
    cb err, @_encrypted

  #-------------

  set_hmac_packet_1 : (b) -> @hmac_packet_1 = b

  #-------------

  to_packet : ({dummy}, cb) ->
    esc = make_esc cb, "Header::to_packet"
    to_buf_args = {}
    if dummy
      await @stubs.estimate_pgp_header_length defer err, len
      @_dummy = pgp = new Buffer (0 for [0...len])
    else
      await @generate esc defer pgp
      to_buf_args.len = @_dummy.len if @_dummy?
    pkt = new HeaderPacket { pgp, @stubs }
    buf = pkt.to_buffer to_buf_args
    cb null, buf

#===============================================================

