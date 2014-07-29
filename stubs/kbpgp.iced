
main = require '../'
pgpu = require 'pgp-utils'
{ASP} = pgpu.util
fs = require 'fs'
{make_esc} = require 'iced-error'
kbpgp = require 'kbpgp'
{KeyManager} = kbpgp
triplesec = require 'triplesec'
{WordArray} = triplesec

#=================================================================================

class File

  constructor : ({@name, @flags, @mode}) ->
    @fd = null

  open : (cb) ->
    console.log "opening ...."
    console.log @name
    console.log @flags
    console.log @mode
    await fs.open @name, @flags, @mode, defer err, @fd
    console.log err
    console.log @fd
    cb err

  read : ( {start, bytes}, cb) ->
    buf = new Buffer bytes
    await fs.read @fd, buf, 0, bytes, start, defer err, bytesRead, buffer
    ret = if err? then null else buf[0...bytesRead]
    cb err, ret

  write : ( {start, buf}, cb) ->
    console.log "writing ..."
    console.log @fd
    console.log @name
    console.log start
    console.log buf
    await fs.write @fd, buf, 0, buf.length, start, defer err, bytesWritten
    console.log err
    console.log bytesWritten
    if not err? and (buf.length isnt bytesWritten)
      err = new Error "short write -- should handle this!"
    cb err

  close : (cb) ->
    await fs.close @fd, defer err
    cb err

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

  init_aes256ctr : ({key, iv}, cb) ->
    @block_cipher = new triplesec.ciphers.AES WordArray.from_buffer key

    # It would be nice to use Triplesec-style full 128-bit CTRs, but SSL
    # and other libraries don't see to want that --- they prefer instead an 8 byte
    # IV and 8 bytes of counter.
    #
    # I'm not too worried since we're using random AES keys...
    pad = new Buffer (0 for [0...8])
    iv = Buffer.concat [ iv, pad ]
    @iv = WordArray.from_buffer iv

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
    await triplesec.hmac.bulk_sign args, defer err, res
    cb err, res?.to_buffer()

  #---------------------------

  read : ({start, bytes}, cb) -> @infile.read { start, bytes}, cb
  write : ({start, buf }, cb) -> @outfile.write { start, buf }, cb

  #---------------------------

  prng : (n, cb) ->
    await kbpgp.rand.SRF().random_bytes n, defer ret
    cb null, ret

  #---------------------------

  close : (cb) ->
    await @outfile.close defer err
    cb err

  #---------------------------

  estimate_pgp_header_length : (cb) ->
    cb null, 300

  #---------------------------

#=================================================================================

key = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQHhBFMFX/YRBACKwOOj7dkyHb8J3qDOvS0ZEcgiZnFCaLCh07GWV/S/HEelVaDF
BIVdn2Ho/j80HWkRMJAFqNBoEfqqz1n6MFxZNgUlWOOSdUIkOq2qcZhqQqcvwqJU
FxKKO7gKI037HBYlgmgD2/LGAWGZQDHDciDqcy+SEwvFB+y/x9bSSCornwCgnVzp
C77KgeXIS26JtbMeNd7x+xkD/3NjzK0jF3v7fASE2Eik+VlGiXkk8IuV32LYAtkd
Qyjw+Xqx6T3gtOEPOJWd0MlOdb75J/EMJYN+10yMCIFgMTUexL4uVRKMRBy3JBwW
kHApO+LG/2g5ZHupaqBixfcpya5N1T+sNNlPQ1pvCTANakp1ELR2BAb6g5PGuQab
scboA/9LsjYMdTqXQVCj9ck0+kSFxeBygobDqQIwd4BW2fMRzRg7kFZdICtzYSSi
2z9iHmzC+OiokPKHnVSYRKSZ5cHe/ke2SunptKzpFhWxKO5FYRODX3txvEMUUst+
FE1f/+dnLQyxY5BB1fRcpUlUtRZ453lObMm0aY652bgyW/6CSP4DAwJVX0fqCIms
8WC03phNbtqDYUIajoX+e+p8wBBUNRZo4JSV8s7OTI+MMTR0MO38+9B+cM9KKmbG
A0Clx7Q3R2VvcmdlcyBCZW5qYW1pbiBDbGVtZW5jZWF1IChwdyBpcyAnYWJjZCcp
IDxnYmNAZ292LmZyPohoBBMRAgAoBQJTBV/2AhsDBQkSzAMABgsJCAcDAgYVCAIJ
CgsEFgIDAQIeAQIXgAAKCRA350+UAcLjmJWYAKCYHsrgY+k3bQ7ov2XHf9SjX7qU
twCfebPu3y0/Ll7OdCw5fcXuzbCUbjY=
=s2F5
-----END PGP PRIVATE KEY BLOCK-----
"""

pp = 'abcd'


test = ({infile, outfile}, cb) ->
  esc = make_esc cb, "test"
  await KeyManager.import_from_armored_pgp { raw : key  }, esc defer km
  await km.unlock_pgp { passphrase : pp }, esc defer()
  stubs = new Stubs { infile, outfile, encrypt_for : km }
  await main.encrypt { stubs }, esc defer()
  cb null

await test {infile : 'x', outfile :'y' }, defer err
console.log err



