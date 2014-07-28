
main = require '../'
pgpu = require 'pgp-utils'
{ASP} = pgp.util
fs = require 'fs'
{make_esc} = require 'iced-error'
kbpgp = require 'kbpgp'
triplesec = require 'triplesec'
{WordArray} = triplesec

#=================================================================================

class File

  constructor : ({@name, @flags, @mode}) ->
    @fd = null

  open : (cb) ->
    await fs.open @name, @flags, @mode, defer err, @fd
    cb err

  read : ( {start, bytes}, cb) ->
    buf = new Buffer bytes
    await fs.read @fd, buf, 0, bytes, start, defer err, bytesRead, buffer
    ret = if err? then null else buf[0...bytesRead]
    cb err, ret

  write : ( {start, buf}, cb) ->
    await fs.write @fd, buf, 0, buf.length, start, defer err, bytesWritten
    if err? and (buf.length isnt bytesWritten)
      err = new Error "short write -- should handle this!"
    cb err

  get_length : (cb) ->
    await fs.fstat @fd, defer err, stat
    ret = if err? then null else stat.size
    cb err, ret

#=================================================================================

class Stubs extends main.Stubs

  #---------------------------

  constructor : ({asp, infile, outfile, @config, @encrypt_for, @sign_with, @keyfetch}) ->
    super()
    @asp = ASP.make asp
    @infile = new File { name : infile, flags : "r" }
    @outfile = new File { name : outfile, flags : "w", mode : (@config?.mode or 0o640) }

  #---------------------------

  init : (args, cb) ->
    esc = make_esc cb, "Stubs::init"
    await @infile.open esc defer()
    await @outfile.open esc defer()
    cb null

  #---------------------------

  encrypt_pgp_header : ({buf}, cb) ->
    await kbpgp.box { msg : buf, @sign_with, @encrypt_for }, defer err, ascii, raw
    cb err, raw

  #---------------------------

  decrypt_pgp_header : ({buf}, cb) ->
    await kbpgp.unbox { raw : buf, @keyfetch }, defer err, literals
    if err? then # noop
    else if literals.length isnt 1 then new Error "Expected only one literal"
    else
      lit = literals[0]
      out = lit.toString()
      sig = lit.get_data_signer()
    cb err, out, sig

  #---------------------------

  init_aes256_ctr : ({key, iv}, cb) ->
    @block_cipher = new triplesec.ciphers.AES WordArray.from_buffer key

    # It would be nice to use Triplesec-style full 128-bit CTRs, but SSL
    # and other libraries don't see to want that --- they prefer instead an 8 byte
    # IV and 8 bytes of counter.
    #
    # I'm not too worried since we're using random AES keys...
    @iv = WordArray.from_buffer Buffer.concat(iv, (new Buffer (0 for i in [0...8])) )

    # Here's the stream-style cipher with a constantly-incrementing nonce
    # via the counter.
    @cipher = triplesec.modes.CTR.Cipher { @block_cipher, @iv }

    cb null

  #---------------------------

  init_hmac_sha256 : ({key}, cb) ->
    @hmac_key = WordArray.from_buffer key
    cb null

  #---------------------------

  aes256ctr_encrypt : ({buf}, cb) ->
    args =
      input : WordArray.from_buffer(buf)
      progress_hook : @asp.progress_hook.bind(@asp)
      what : "AES"
    await @cipher.bulk_encrypt args, defer err, ret
    cb err, ret?.to_buffer()

  #---------------------------

  aes256ctr_decrypt : ({buf}, cb) -> @aes256ctr_encrypt { buf }, cb

  #---------------------------

  hmac_sha256 : ({buf}, cb) ->
    args =
      key : @hmac_key
      input : WordArray.from_buffer buf
      progress_hook : @asp.progress_hook.bind(@asp)
      what : "HMAC"
      klass : triplesec.hmac.HMAC_SHA256
    await triplesec.bulk_sign args, defer err, res
    cb err, res?.to_buffer()

  #---------------------------

  read : ({start, bytes}, cb) -> @infile.read { start, bytes}, cb
  write : ({start, buf }, cb) -> @infile.write { start, buf }, cb
  get_length : (cb) -> @infile.get_length cb

  #---------------------------

#=================================================================================

