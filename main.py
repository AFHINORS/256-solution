import lzma
exec(lzma.decompress(open('/app/p','rb').read(),format=3,filters=[{'id': 33, 'preset': 2147483657, 'lc': 2, 'lp': 0, 'pb': 0}]))
