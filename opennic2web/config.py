

class Config:
	"""
	The Opennic2Web configuration object
	"""
	def __init__(self,
		hostname = b'localhost', # FIXME change default hostname
		block_hotlink_exts = b'jpg png gif'.split()
		):
		self.hostname = hostname
		self.block_hotlink_exts = block_hotlink_exts