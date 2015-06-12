import logging
import http
import profile
import event
import json
import ast
import dpid
import signal
import os

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)




class Base(object):
	def __init__(self):
		self.classname = self.__class__.__name__
		self.logging = logging.getLogger(self.classname)
		self.ROUTER = '/router'
		self.STATS_FLOW_PATH = '/stats/flow'
		self.LOADBALANCE_VSERVER_PATH = '/loadbalance/vserver'
		self.LOADBALANCE_ASERVER_PATH = '/loadbalance/aserver'
		

	def _exe_http_aserver(self, controller, content):
		aserver_url = controller + self.LOADBALANCE_ASERVER_PATH
		_content = json.dumps(content)
		self.http.post(aserver_url, _content)

	def _exe_http_vserver(self, controller, content):
		url = controller + self.LOADBALANCE_VSERVER_PATH
		_content = json.dumps(content)
		self.http.post(url, _content)

	def _exe_http_virtual_ip(self, controller, dpid, content):
		url = controller + self.ROUTER + '/' + dpid
		_content = json.dumps(content)
		self.http.post(url, _content)
		self.logging.debug("set vserver = \n    %s", content)

	def _exe_http_clear_switch(self, controller, dpid):
		url = controller + self.ROUTER + '/' + dpid
		_content = json.dumps({"route_id": "all"})
		self.http.delete(url, _content)
		_content = json.dumps({"address_id": "all"})
		self.http.delete(url, _content)

	def _set_aprofile_to_controller(self, controller, local_aprofiles ):
		requests = []
		for l in local_aprofiles:
			self._exe_http_aserver(controller, l)	

	def _set_vprofile_to_controller(self, controller, local_vprofiles ):
		remote_vprofile = self._get_remote_vprofile(controller)
		requests = []

		for l in local_vprofiles:
			local = None
			for r in remote_vprofile:
				if r["vserver_name"] == l["vserver_name"]:
					local = l
					remote = r

			# if remote don't exist, then add min(priority)
			if local == None:
				services = self._choose_services(None, l)
			# if remote exists , then add next(priority)	
			else : 
				services = self._choose_services(remote, local)
			
			req = { "vserver_name": l["vserver_name"],
					"default_server_ip": l["default_server_ip"],
					"vserver_ip" : l["vserver_ip"],
					"turn_to_services" : services}
			self._exe_http_vserver(controller, req)
	
	def _set_virtual_ip_to_switch(self, controller, dpid, ip):
		url = controller + self.ROUTER + '/' + dpid
		_content = json.dumps({"address": ip})
		self.http.post(url, _content)
		self.logging.info('virtual_ip=%s' % ip)

	def _set_virtual_gw_to_switch(self, controller, dpid, ip):
		url = controller + self.ROUTER + '/' + dpid
		_content = json.dumps({"gateway": ip})
		status, content = self.http.post(url, _content)
		self.logging.info('virtual_gw=%s' % ip)

	def _clear_switch(self, controller, dpid):
		self._exe_http_clear_switch(controller, dpid)		

	def _get_remote_vprofile(self, controller):
		url = controller + self.LOADBALANCE_VSERVER_PATH + '/all'
		status, rest_content = self.http.get(url)
		if status == 200 : 
			ujson = json.loads(rest_content)
			result = ast.literal_eval(json.dumps(ujson)) if ujson else []
			return result
		else : return []

class RandomMode (Base) :
	def __init__(self, prof):
		super(RandomMode, self).__init__()
		self.classname = self.__class__.__name__
		self.logging = logging.getLogger(self.classname)
		
		self.local_prof = prof
		self.local_controller = self.local_prof.get_controller()
		self.local_dpid = self.local_prof.get_dpid()
		self.local_aprofiles = self.local_prof.get_actual_profile()
		self.local_vprofiles = self.local_prof.get_virtual_profile()
		self.http = http.HttpClient()
		self.is_active = True
		self.exit = False

	def __call__(self):
		self._loop()

	def _choose_services(self, remote, local):
		lists = []
		if remote == None:	
			local_services = local["turn_to_services"]
			for ls in local_services:
				sort = sorted(ls["dst_servers"], 
									key=lambda k: k["priority"]) 
				service = {}
				service["service"] = ls["service"]
				service["ip"] = sort[0]["ip"]
				service["priority"] = sort[0]["priority"]
				service["ipproto"] = sort[0]["ipproto"]
				lists.append(service)
		else :
			remote_services = remote["turn_to_services"]
			local_services = local["turn_to_services"]

			for ls in local_services:
				match1 = False
				service = {}
				for rs in remote_services:
					if ls["service"] == rs["service"]: 
						sort = sorted(ls["dst_servers"], 
									key=lambda k: k["priority"]) 
						# set default 
						service["service"] = ls["service"]
						service["ip"] = sort[0]["ip"]
						service["priority"] = sort[0]["priority"]
						service["ipproto"] = sort[0]["ipproto"]

						match2 = False
						for s in sort :
							if match2 == True:
								service["ip"] = s["ip"]
								service["priority"] = s["priority"]
								service["ipproto"] = s["ipproto"]
								break
							if s["priority"] == rs["priority"]:
								match2 = True			
						match1 = True
						lists.append(service)
						break
	
				if match1 == False :
					service["service"] = ls["service"]
					sort = sorted(ls["dst_servers"], 
									key=lambda k: k["priority"]) 
					# set default 
					service["service"] = ls["service"]
					service["ip"] = sort[0]["ip"]
					service["priority"] = sort[0]["priority"]
					service["ipproto"] = sort[0]["ipproto"]
					lists.append(service)
		return lists

	def stop(self):
		self.logging.info('Stop thread[%s]' % self.classname)
		self.is_active = False

	def _loop(self):
		# clear switch setting
		self._clear_switch(self.local_controller, self.local_dpid)

		# set actual server to controller
		self._set_aprofile_to_controller(self.local_controller, self.local_aprofiles)
		
		# set virtual server to controller
		lists = []
		for vp in self.local_vprofiles:
			if vp["enable"] == "true":
				vserver_ip = vp["vserver_ip"]
				vserver_gw = vp["vserver_gw"]
				self._set_virtual_ip_to_switch(self.local_controller, self.local_dpid, vserver_ip)
				self._set_virtual_gw_to_switch(self.local_controller, self.local_dpid, vserver_gw)
				lists.append(vp)

		while self.is_active :
			self._set_vprofile_to_controller(self.local_controller, lists)
			event.sleep(5)

		self.exit = True
	def wait(self):
		while self.exit :
			event.sleep(1)


class StatisticsMode (Base) :
	def __init__(self, prof):
		super(StatisticsMode, self).__init__()
		self.classname = self.__class__.__name__
		self.logging = logging.getLogger(self.classname)
		self.local_prof = prof
		self.local_controller = self.local_prof.get_controller()
		self.local_dpid = self.local_prof.get_dpid()
		self.local_aprofiles = self.local_prof.get_actual_profile()
		self.local_vprofiles = self.local_prof.get_virtual_profile()
		self.http = http.HttpClient()
		self.is_active = True
		self.ipproto = {"tcp":"6", "6":"tcp", "udp":"17", "17":"udp"}
		self.exit = False

	def __call__(self):
		self._loop()

	def stop(self):
		self.logging.info('Stop thread[%s]' % self.classname)
		self.is_active = False

	def _get_all_rest_flow_entrys(self, controller, _dpid):
		url = controller + self.STATS_FLOW_PATH + '/' + _dpid
		status, rest_content = self.http.get(url)
		if status == 200 : 
			ujson = json.loads(rest_content)
			result = ast.literal_eval(json.dumps(ujson)) if ujson else []
			return result[str(dpid.str_to_dpid(_dpid))] 
		else : return []

	def __count_session_by_aserver(self, flowentrys, service):		
		count = {}
		dst_servers = service["dst_servers"]
		for s in dst_servers:
			count[s["ip"]] = 0

		for fe in flowentrys:
			# use priority as id
			if fe["priority"] == 5000:
				match = fe["match"]

				actions =  fe["actions"]
				for ip in count.keys():
					for action in actions:
						if action.find("ipv4_dst:"+ip) != -1:
							val = count[ip]
							count[ip] = val + 1 
							break
		return count


	def _count_rest_flow_entry(self, flowentrys):
		count = {}
		for fe in flowentrys:
			# use priority as id
			if fe["priority"] == 5000:
				actions = fe["actions"]
				value = actions[2].split("SET_FIELD: ")
				ipv4_dst = value[1][1:-1].split(":")[1]
				match = fe["match"]

				key = str(ipv4_dst) + \
					'-' + str(match["tp_dst"])  + \
					'-' + str(match["nw_proto"])
				val = count.setdefault(key)  
				if val == None: count[key] = 1
				else : count[key] += 1
		return count

	def _count_session(self, controller, dpid, actual_profile, vprofile):
		flowentrys = self._get_all_rest_flow_entrys(controller, dpid)
		count = self._count_rest_flow_entry(flowentrys)

	
		vserver_ip = vprofile["vserver_ip"].split("/")[0]
		turn_to_services = vprofile["turn_to_services"]
		for s in turn_to_services:
			service = s["service"]
			dst_servers = s["dst_servers"]

			for dst_server in dst_servers:
				key = str(dst_server["ip"]) + \
					'-' + str(service[0]) + \
					'-' + self.ipproto[dst_server["ipproto"]]
				val = count.setdefault(key)
				if val == None:
					count[key] = 0
		# calculate ip of min
		mmin = {} 
		for ck in count.keys() :
			v = ck.split("-")
			ip = v[0]
			service = v[1]
			ipproto = v[2]
			key = service + '-' + ipproto
			value = mmin.setdefault(key)
			if value == None :
				mmin[key] = ip + "-" + str(count[ck])
			else :
				v2 = value.split("-")
				if int(count[ck]) < int(v2[1]):
					mmin[key] = ip + "-" + str(count[ck])	

		request = {}
		request["default_server_ip"] = vprofile["default_server_ip"]
		request["vserver_name"] = vprofile["vserver_name"]
		request["vserver_ip"] = vprofile["vserver_ip"]

		services = []
		for s in turn_to_services:
			for m in mmin.keys():
				v = m.split("-")
				ip = mmin[m].split("-")[0]
				if v[0] == str(s["service"][0]):
					for dst_server in s["dst_servers"]:
						if dst_server["ip"] == ip and \
							dst_server["ipproto"] == self.ipproto[v[1]]:
							priority = dst_server["priority"]
							break
					service = {"service":s["service"],
						"ipproto":	self.ipproto[v[1]],
						"priority": priority,
						"ip": ip}
					services.append(service)

		request["turn_to_services"] = services
		self._exe_http_vserver(controller, request)
		self.logging.debug('\n%s\n' % request)

	def _loop(self):
		# clear switch setting
		#self._clear_switch(self.local_controller, self.local_dpid)
		# set actual server to controller
		self._set_aprofile_to_controller(self.local_controller, self.local_aprofiles)
		
		vprofile = []
		for vp in self.local_vprofiles:
			if vp["enable"] == "true":
				vserver_ip = vp["vserver_ip"]
				vserver_gw = vp["vserver_gw"]
				self._set_virtual_ip_to_switch(self.local_controller, self.local_dpid, vserver_ip)
				self._set_virtual_gw_to_switch(self.local_controller, self.local_dpid, vserver_gw)
				vprofile.append(vp)

		# set actual server to controller
		while self.is_active :
			for vp in vprofile:
				self._count_session(
					self.local_controller, self.local_dpid, self.local_aprofiles, vp)
			event.sleep(1)
			
	def wait(self):
		while self.exit :
			event.sleep(1)
	

is_active = True
def signal_handler(signum, frame):
	global is_active
	if signum == signal.SIGINT:
		is_active = False


def init_signal():
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGINT, signal_handler)
	

if __name__ == '__main__':
	init_signal()
	threads = []
	try :
		while is_active:
			is_nochange = True	
				
			LOG.info('Loading profile.json')			
			prof = profile.Profile("profile.json")
			mode = prof.get_mode()
			
			if mode == 1:
				LOG.info('Execute RandomMode')
				#threads.append(event.spawn(RandomMode(prof)))
				threads.append(RandomMode(prof))
				for t in threads: event.spawn(t)
			elif mode == 2:
				LOG.info('Execute StatisticsMode')
				#threads.append(event.spawn(StatisticsMode(prof)))
				threads.append(StatisticsMode(prof))
				for t in threads: event.spawn(t)

			while is_active:
				event.sleep(1)
				
	except Exception as e:
		pass
	finally:
		for t in threads:
			t.stop()
		event.joinall(threads)
		# close 

