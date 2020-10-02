
import json
from asysocks.intercepting.target import InterceptTarget

default_table_data = json.loads("""
[
	{
		"dsthost" : ".*",
		"dstport" : 443,
		"proto" : "http",
		"ssl" : true
	},
	{
		"dsthost" : ".*",
		"dstport" : 80,
		"proto" : "http",
		"ssl" : false
	}
]
""")

default_intercept_table = []
for x in default_table_data:
	default_intercept_table.append(InterceptTarget.from_dict(x))