
from asysocks.intercepting.monitors.base import BaseMonitor
from asysocks.intercepting.monitors.sslbase import SSLBaseMonitor
from asysocks.intercepting.monitors.rawlogging import RawLoggingMonitor

prototable = {
	'http' : RawLoggingMonitor,
	'rawlog' : RawLoggingMonitor,
	'ssllog' : None,
}