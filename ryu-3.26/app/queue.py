class CommandStats(object):
    def __init__(self, size):
        super(CommandStats, self).__init__()
        self.cmdList = []
	self.size = size
	

    def append(self, data):
	if len(self.cmdList) >= self.size:
		del self.cmdList[0]
        self.cmdList.append(data)
    

s = CommandStats(2)
s.append(1)
s.append(2)
s.append(3)
s.append(4)
print s.cmdList
