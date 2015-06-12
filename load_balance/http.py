import urllib
import urllib2
# status codes
# informational
HTTP_CONTINUE = 100
HTTP_SWITCHING_PROTOCOLS = 101
HTTP_PROCESSING = 102

# successful
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_HTTP_ACCEPTED = 202
HTTP_NON_AUTHORITATIVE_INFORMATION = 203
HTTP_NO_CONTENT = 204
HTTP_RESET_CONTENT = 205
HTTP_PARTIAL_CONTENT = 206
HTTP_MULTI_STATUS = 207
HTTP_IM_USED = 226

# redirection
HTTP_MULTIPLE_CHOICES = 300
HTTP_MOVED_PERMANENTLY = 301
HTTP_FOUND = 302
HTTP_SEE_OTHER = 303
HTTP_NOT_MODIFIED = 304
HTTP_USE_PROXY = 305
HTTP_TEMPORARY_REDIRECT = 307

# client error
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_PAYMENT_REQUIRED = 402
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_METHOD_NOT_ALLOWED = 405
HTTP_NOT_ACCEPTABLE = 406
HTTP_PROXY_AUTHENTICATION_REQUIRED = 407
HTTP_REQUEST_TIMEOUT = 408
HTTP_CONFLICT = 409
HTTP_GONE = 410
HTTP_LENGTH_REQUIRED = 411
HTTP_PRECONDITION_FAILED = 412
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
HTTP_REQUEST_URI_TOO_LONG = 414
HTTP_UNSUPPORTED_MEDIA_TYPE = 415
HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416
HTTP_EXPECTATION_FAILED = 417
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_LOCKED = 423
HTTP_FAILED_DEPENDENCY = 424
HTTP_UPGRADE_REQUIRED = 426

# server error
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_NOT_IMPLEMENTED = 501
HTTP_BAD_GATEWAY = 502
HTTP_SERVICE_UNAVAILABLE = 503
HTTP_GATEWAY_TIMEOUT = 504
HTTP_VERSION_NOT_SUPPORTED = 505
HTTP_INSUFFICIENT_STORAGE = 507
HTTP_NOT_EXTENDED = 510


class HttpClient(object):
	def __init__(self):
		super(HttpClient, self).__init__()

	def get(self, url):
		status = ""
		content = ""
		try :
			rep = urllib2.urlopen(url)
			status = rep.getcode()
			content = rep.read()
			rep.close()
		except urllib2.HTTPError as e:
			status = e.code
			content = e.reason
		return status, content

	def post(self, url, data):
		status = ""
		content = ""
		try :
			req = urllib2.Request(url=url,data=data)
			req.add_header('content-type', 'application/json')
			req.add_header('accept', '*/*')
			rep = urllib2.urlopen(req)
			status = rep.getcode()
			content = rep.read()
			rep.close()
		except urllib2.HTTPError as e:
			status = e.code
			content = e.reason
		return status, content

	def delete(self, url, data):
		status = ""
		content = ""
		try :
			req = urllib2.Request(url=url,data=data)
			req.add_header('content-type', 'application/json')
			req.add_header('accept', '*/*')
			req.get_method = lambda : 'DELETE'
			rep = urllib2.urlopen(req)
			status = rep.getcode()
			content = rep.read()
			rep.close()
		except urllib2.HTTPError as e:
			status = e.code
			content = e.reason
		return status, content

#http = HttpClient()
#print http.get("http://ubuntu:8080/loadbalance/vserver/all")
#print http.delete("http://ubuntu:8888/router/0000000000000002",'{\"address_id\":\"all\""}')