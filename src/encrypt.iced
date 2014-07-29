
{make_esc} = require 'iced-error'
{Index} = require './index'
{Header} = require './header'
C = require './const'
{DataPacket} = require './packet'
{PacketWriter} = require './io'

#===============================================================

exports.Encryptor = class Encryptor

  constructor : ({@stubs, config}) ->
    @_index = new Index { @stubs }
    @_data = { cipeher : {}, hmac : {} }
    @_packet_writer = new PacketWriter { @stubs }
    @config = config or {}
    @config.blocksize or= C.defaults.blocksize
    @config.hashes_per_index_packet or= C.defaults.hashes_per_index_packet

  #------------------------

  run : (cb) ->
    esc = make_esc cb, "Encryptor::run"
    await @_init esc defer()
    await @_generate_keys esc defer()
    await @_write_header { dummy : true }, esc defer()
    await @_write_file esc defer()
    await @_generate_index esc defer()
    @_packet_writer.rewind()
    await @_write_header { dummy : false }, esc defer()
    await @_write_index esc defer()
    await @stubs.flush esc defer()
    cb null

  #------------------------

  init : (cb) ->
    await @stubs.init {}, defer err
    cb err

  #------------------------

  _generate_keys : (cb) ->
    esc = make_esc cb, "Encryptor::_generate_keys"
    await @stubs.prng C.cipher.key_size, esc defer @_data.cipher.key
    await @stubs.prng C.cipher.iv_size,  esc defer @_data.cipher.iv
    await @stubs.prng C.hmac.key_size,   esc defer @_data.hmac.key

    await @stubs.init_aes256ctr @_data.cipher, esc defer()
    await @stubs.init_hmac_ah256 @_data.hmac , esc defer()

    @_hdr = new Header { @stubs, keys : @_data }
    cb null

  #------------------------

  _write_index : (cb) ->
    await @_packet_writer.write { packets : @_index_packets }, defer err
    cb err

  #------------------------

  _write_header : (opts, cb) ->
    esc = make_esc cb, "Encryptor::_write_dummy_header"
    await @_hdr.to_packet opts, esc defer packet
    await @_packet_writer.write {packet}, esc defer()
    cb null

  #------------------------

  _write_dummy_index_packet : ({packetno}, cb) ->
    esc = make_esc cb, "Encryptor::_write_dummy_index_packet"
    await @_index.gen { packetno }, esc defer packet
    await @_packet_writer.write { packet }, esc defer index, offset
    packet.set_offset = offset
    cb null

  #------------------------

  _generate_index : (cb) ->
    await @_index.generate {}, defer err, @_index_packets
    @_hdr.set_hmac_packet_1 @_index_packets[0].hmac
    cb err

  #------------------------

  _write_file : (cb) ->
    esc = make_esc cb, "Encryptor::_write_file"
    go = true
    i = 0
    while go
      if (i % @const.hashes_per_index_packet) is 0
        await @_write_dummy_index_packet { packetno : (i+1) }, esc defer()
      await @stubs.read esc defer buf, eof
      go = false if eof
      packet = new DataPacket { buf, @stubs }
      await packet.encrypt esc defer()
      await @_packet_writer.write { packet }, esc defer index
      @_index.index { index, hmac : packet.hmac }
      i += @config.blocksize
    cb null

#===============================================================

exports.encrypt = ({stubs, config}, cb) ->
  e = new Encryptor { stubs, config }
  await e.run defer err
  cb err

#===============================================================

