
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

try:
	"".remove_suffix("")
	def remove_suffix(v, s):
		v.remove_suffix(s)
except:
	def remove_suffix(v, s):
		return v[:-len(s)] if v.endswith(s) else v
