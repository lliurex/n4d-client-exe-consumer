import xmlrpc.client
import tempfile
import os
import os.path
import stat
import time
import subprocess
import netifaces
import n4d.server.core
import n4d.responses
import ssl

 
class ClientExeConsumer:
	
	LOG_FILE="/var/log/n4d/client-consumer"

	def __init__(self):

		self.core=n4d.server.core.Core.get_core()

	#def __init__	
	
	def startup(self,options):
	
		if not self.check_semiclient():
			
			if not self.core.variable_exists('CLIENT_EXE_SERVER').get('return',None):
				self.core.set_variable('CLIENT_EXE_SERVER','server')
			
			# one shots
			
			try:
			
				self.read_log()
				ret=self.get_oneshots()
				self.execute_and_delete(ret)
				
			except Exception as e:
				print(str(e))
			
		# boot scripts
		
		try:
			mac=self.get_mac_from_ip(self.get_ip_from_cmdline())
			self.execute_boot_scripts(mac)
		except Exception as e:
			print(str(e))
		
	#def startup



	def read_log(self):
		
		self.md5_log=[]
		
		try:
			f=open(ClientExeConsumer.LOG_FILE)
			lines=f.readlines()
			f.close()
		except:
			lines=[]
			try:
				f=open(ClientExeConsumer.LOG_FILE,"w")
				f.close()
			except:
				return -1
		
		for item in lines:
			line=item.strip("\n")
			if len(line)>0:
				self.md5_log.append(line)
		
	#def read_log
	
	def get_oneshots(self):
		
		ret_list=[]
		
		try:
			srv=self.core.get_variable("CLIENT_EXE_SERVER").get('return',None)

			if srv!=None and type(srv)==type(""):
				context=ssl._create_unverified_context()
				c=xmlrpc.client.ServerProxy("https://"+srv+":9779",context=context,allow_none=True)
				ret=c.get_available_oneshots("","ClientExeManager",self.md5_log).get('return',None)
				if type(ret)==type([]):
				
					for item in ret:
						md5,content=item
						content=content.encode("utf-8")
						id,file_name=tempfile.mkstemp(prefix="n4d-cec-")
						os.close(id)
						st=os.stat(file_name)
						os.chmod(file_name,st.st_mode | stat.S_IEXEC)
						script=open(file_name,"w")
						script.write(content)
						script.close()
						ret_list.append(file_name)
						self.add_md5(md5)
				
		except Exception as e:
			print(str(e))
			pass
		
		return ret_list
		
		
	#def get_exes
	
	def add_md5(self,md5):
		
		self.read_log()
		if md5 not in self.md5_log:
			f=open(ClientExeConsumer.LOG_FILE,"a")
			f.write(md5+"\n")
			f.close()
			self.md5_log.append(md5)
			
	#def add_md5
	
	def execute_and_delete(self,file_list,delete=True):
		
		for item in file_list:
			print ("[ClientExeConsumer] Executing " + item +" ...")
			os.system(item)
			if delete:
				os.remove(item)
				
	#def execute_and_delete
	
	
	def check_semiclient(self):
		
		return os.path.exists("/etc/lts.conf")
		
	#def check_semiclient
	
	
	def force_execution(self,force_all=False):
	
		if not self.check_semiclient():
	
			try:
				if force_all:
					self.md5_log=[]
				
				ret=self.get_oneshots()
				self.execute_and_delete(ret)
				
				if force_all:
					self.read_log()
			
				#Old n4d:return [True,""]
				return n4d.responses.build_successful_call_response(True)
			except Exception as e:
				print(str(e))
				#Old n4d:return [False,str(e)]
				return n4d.responses.build_successful_call_response(False,str(e))
				
		else:
			#Old n4d:return [False,"Semiclient found"]
			return n4d.responses.build_successful_call_response(False,"Semiclient found")
		
	#def force_execution
	
	
	def get_mac_from_ip(self,ip):
	
	
		for item in netifaces.interfaces():
			info=netifaces.ifaddresses(item)
			try:
				if info[netifaces.AF_INET][0]["addr"]==ip:
					return info[netifaces.AF_LINK][0]["addr"]
			except Exception as e:
				print(str(e))
				
		return None
		
	#def get_mac_from_ip
	
	def get_ip_from_cmdline(self):
		
		path="/proc/cmdline"
		
		if os.path.exists(path):
			f=open(path)
			
			for line in f.readlines():
				if "ip=" in line:
					tmp=line.split("ip=")[1]
					tmp=tmp.split(" ")[0]
					ip=tmp.split(":")[0]
					
					return ip
					
		return None
		
	#def get_ip_from_cmdline

	
	def execute_boot_scripts(self,mac):
		
		srv=self.core.get_variable("CLIENT_EXE_SERVER").get('return',None)
		
		if srv==None:
			srv="server"

		context=ssl._create_unverified_context()
		c=xmlrpc.client.ServerProxy("https://%s:9779"%srv,context=context,allow_none=True)
		ret=c.get_boot_scripts("","ClientExeManager",mac)

		if ret["status"]==0:
				
			f_list=[]
				
			for file_content in ret["return"]:
					
				tmp=tempfile.mkstemp()
				f=open(tmp[1],"w")
					
				for line in file_content:
					f.write(line)
				f.close()
				os.close(tmp[0])
				f_list.append(f.name)
					
			for f in f_list:
				os.system("chmod +x %s; %s || true"%(f,f))
				os.remove(f)
				
	#def execute_boot_scripts
	
	
	
#class ClientExeConsumer

if __name__=="__main__":
	
	cec=ClientExeConsumer()
	cec.startup(None)