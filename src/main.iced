
mods = [
  require('./encrypt')
  require('./stubs')
]

for mod in mods
  for k,v of mod
    exports[k] = v
