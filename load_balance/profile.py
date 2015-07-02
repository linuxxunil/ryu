import json
import ast

class ProfileException(Exception):
    message = 'An unknown exception'

    def __init__(self, msg=None, **kwargs):
        self.kwargs = kwargs
        if msg is None:
            msg = self.message

        try:
            msg = msg % kwargs
        except Exception:
            msg = self.message

        super(ProfileException, self).__init__(msg)


class Profile(object):
    def __init__(self, path):
        with open(path) as json_file:
		try :
            		udata = json.load(json_file)
            		self.data = ast.literal_eval(json.dumps(udata))
		except Exception as err:
			raise ProfileException(str(err))


    def __str__(self):
        return json.dumps(self.data) \
                    if self.data else {}	
	
    def get_version(self):
        return self.data["version"]

    def get_enable(self):
        return self.data["enable"]

    def get_virtual_profile(self):
        return self.data["virtual_profile"]

    def get_actual_profile(self):
        return self.data["actual_profile"]

    def get_controller(self):
        return self.data["controller"]
    
    def get_dpid(self):
        return self.data["dpid"]
    
    def get_mode(self):
        return self.data["mode"]