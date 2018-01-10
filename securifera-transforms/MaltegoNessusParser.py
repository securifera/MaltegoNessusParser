import ipaddress
import xml.etree.ElementTree as ET
from sets import Set
from MaltegoTransform import *
import time
import Tkinter as tk
import glob
import os

########################################
#Constants
########################################
NESSUSSCANPROP = "nessusscan"
NESSUSSCANPROPDIS = "Nessus Scan"
NESSUSSCANPATHPROP = "nessusscanpath" #TODO update this
NESSUSSCANPATHPROPDIS = "Nessus Scan Path"
#badXML = [("'",'&apos;'),("<","&lt;"),(">","&gt;"),("&","&amp;"),("\"","&quot;")]
badXML = [("<","("),(">",")")]
STATMODE = "stat"
GATHERPLUGINMODE = "gather_plugin"
IPENTITYMODE = "ip_entity"
PLUGINENTITYMODE = "plugin_entity"

########################################
#Global variables
########################################
uniquePluginIds = Set()
uniqueHosts = Set()
allHosts = []
parseMode = "stats"
uniquePlugins = Set()
defaultPluginFilter = "10908,95928,10860,10399,72684,10902,10107,24260,22964,11219,34252,10267,21186,10092,20285,31411,10144,22073,26024,17975,11153,11154,20301,63061,57396,10263,10144,35371,10719,11002"
pluginIncludeList = []

pluginInfo = {}
serviceMap = {}
userAccounts = []

########################################
#Maltego Entity Types
########################################

class EntityProperty(object):
	
	def __init__(self, name, display, value):
		self.fieldName = name
		self.displayName = display
		self.value = value
		
class MaltegoEntity:
	
	def __init__(self, entType, desc):
		self.entType = entType
		self.entDesc = desc
		self.custom = []
		self.note = ''
				
	def addCustomProperty(self, prop):
		self.custom.append(prop)
				
	def addEntity(self, maltegoMsg):
		ent = maltegoMsg.addEntity(self.entType, self.entDesc)
		if self.note != '':
			ent.setNote(self.note)
		
		#Add custom properties
		for prop in self.custom:
			ent.addProperty(fieldName=prop.fieldName,displayName=prop.displayName,value=prop.value)
		return ent

class IPv4Address(MaltegoEntity):

	def __init__(self, ip, hostname=''):
		MaltegoEntity.__init__(self, "maltego.IPv4Address", ip)
		self.hostname = hostname
		
	def addEntity(self, maltegoMsg):
		ent = MaltegoEntity.addEntity(self, maltegoMsg)
		if self.hostname != '':
			ent.addProperty(fieldName="fqdn",displayName="DNSName",value=self.hostname)
		return ent		

class Port(MaltegoEntity):
	
	def __init__(self, port):
		MaltegoEntity.__init__(self, "maltego.Port", str(port))
		self.port = port	
						
	def addEntity(self, maltegoMsg):
		ent = MaltegoEntity.addEntity(self, maltegoMsg)
		ent.addProperty(fieldName="port.number",displayName="Port", value=self.port)
		return ent

class Service(Port):
	
	def __init__(self, port, banner):
		Port.__init__(self, port)
		self.description = banner + ':' + port
		self.banner = banner
		self.service = banner + ':' + port
		self.note = ""
		
	def setBanner(self, banner):
		self.description = banner + ':' + self.port
		self.banner = banner
		self.service = banner + ':' + self.port
						
	def addEntity(self, maltegoMsg):
	
		if self.banner != '':
			self.entType = "maltego.Service"
			self.entDesc = self.description
		
		#Create the base entity
		ent = Port.addEntity(self, maltegoMsg)	
		if self.banner != '':
			ent.addProperty(fieldName="banner.text",displayName="Service banner",value=self.banner)
			ent.addProperty(fieldName="properties.service",displayName="Service",value=self.service)

class Alias(MaltegoEntity):
	def __init__(self, username, da=False, la=False):
		MaltegoEntity.__init__(self, "maltego.Alias", username)
		self.da = da
		self.la = la
		
	def addEntity(self, maltegoMsg):
		ent = MaltegoEntity.addEntity(self, maltegoMsg)
		if self.da is True:
			ent.addProperty(fieldName="alias.da",displayName="Domain Admin",value=str(self.da))
		if self.la is True:
			ent.addProperty(fieldName="alias.la",displayName="Local Admin",value=str(self.la))
		return ent


########################################
#Utility functions
########################################

def sanitize(aLine, tupleList=[]):
	if len(tupleList) < 1:
		return aLine
	
	for tup in tupleList:
		aLine = aLine.replace(tup[0], tup[1])
		
	return aLine

def getNessusScanFiles(fileStr=None):
	global parseMode
	
	#prompt user for file path if none given
	if fileStr is None:
		fileStr = getPromptUser("Input file path to Nessus scan", "Nessus Scan Path Prompt")
	
	#if given path is directory find all .nessus files
	filePaths = []
	if os.path.isdir(fileStr) is True:
		filePaths = glob.glob(fileStr+"/*.nessus")
	else:
		filePaths = [fileStr]
	
	if parseMode == STATMODE:
		print "Number of Nessus scans:", len(filePaths)
		for file in filePaths:
			print file
		
	return fileStr, filePaths

########################################
#GUI Stuff
########################################

class MessageBox(tk.Toplevel):
	def __init__(self, parent, prompt):
		tk.Toplevel.__init__(self, parent)

		self.label = tk.Label(self, text="NOTICE: "+prompt)
		self.ok_button = tk.Button(self, text="OK", command=self.on_ok)

		self.label.pack(side="top", fill="x", padx=5, pady=5)
		self.ok_button.pack(side="bottom", padx=5, pady=5)
		self.minsize(300, 40)

	def on_ok(self, event=None):
		self.destroy()

	def show(self):
		self.wm_deiconify()
		self.wait_window()
		self.destroy()
		
class DialogPrompt(tk.Toplevel):
	def __init__(self, parent, prompt, title="Dialog Prompt"):
		tk.Toplevel.__init__(self, parent)

		self.var = tk.StringVar()

		self.label = tk.Label(self, text=prompt)
		self.entry = tk.Entry(self, textvariable=self.var)
		self.ok_button = tk.Button(self, text="OK", command=self.on_ok)

		self.label.pack(side="top", fill="x", padx=5, pady=5)
		self.entry.pack(side="top", fill="x", padx=5, pady=5)
		self.ok_button.pack(side="bottom", padx=5, pady=5)

		self.entry.bind("<Return>", self.on_ok)
		
		self.minsize(300, 50)
		self.title(title)
		try:
			#having trouble with icons on linux so just fail gracefully
			self.iconbitmap('logo_icon_16x16.ico')
		except:
			pass

	def on_ok(self, event=None):
		self.destroy()

	def show(self):
		self.wm_deiconify()
		self.entry.focus_force()
		self.wait_window()
		return self.var.get()

class PluginSelector(object):
	def __init__(self, master=None, listcontents=[]):

		self.master = master	
		self.master.attributes('-topmost', True)
		self.createwidgets(listcontents)
				
	def createwidgets(self, listcontent=[]):
		self.entry = tk.Entry(width=35)
		self.contents = tk.StringVar()
		
		self.scrollbar = tk.Scrollbar(self.master, orient=tk.VERTICAL)
		self.listbox = tk.Listbox(self.master, selectmode=tk.EXTENDED, width=35, height=20, yscrollcommand=self.scrollbar.set)
		self.scrollbar.config(command=self.listbox.yview)
		
		self.scrollbar2 = tk.Scrollbar(self.master, orient=tk.VERTICAL)
		self.listbox2 = tk.Listbox(self.master, selectmode=tk.EXTENDED, width=35, height=20, yscrollcommand=self.scrollbar2.set)
		self.scrollbar2.config(command=self.listbox2.yview)
		
		self.button = tk.Button(self.master, text="Select", command=self.buttonCallback)
		self.frame = tk.Frame(self.master)
		self.addbutton = tk.Button(self.frame, text=">>>", command=self.addButtonCallback)
		self.removebutton = tk.Button(self.frame, text="X", command=self.removeButtonCallback)
		self.listcontent = listcontent
		
		self.label = tk.Label(self.master, text="")
		self.label2 = tk.Label(self.master, text="")
		self.selected = []
		
		#contents config
		self.contents.set("filter text here")
		
		#scrollbar config
		self.scrollbar.config(command=self.listbox.yview)
		
		#listbox config
		for item in listcontent:
			self.listbox.insert(tk.END, item)
		self.label.config(text=str(len(self.listbox.get(0, tk.END))))
		
		#listbox2 config
		global defaultPluginFilter
		defaultList = self.filter(defaultPluginFilter)
		for i in defaultList:
			self.listbox2.insert(tk.END, i)
		self.label2.config(text=str(len(self.listbox2.get(0, tk.END))))
		
		#entry config
		self.entry.bind('<Key-Return>', self.enterCallback)
		self.entry["textvariable"] = self.contents
		
		#gui layout
		self.entry.grid(row=0, column=0)
		self.listbox.grid(row=1, column=0)
		self.scrollbar.grid(row=1, column=1, sticky='ns')
		self.frame.grid(row=1, column=2)
		self.listbox2.grid(row=1, column=3)
		self.scrollbar2.grid(row=1, column=4, sticky='ns')
		self.button.grid(row=6, column=2)
		self.label.grid(row=5, column=0)
		self.label2.grid(row=5, column=3)
		
		self.addbutton.pack(side="top")
		self.removebutton.pack(side="top")
		
	def filter(self, filterText=""):
		filterTextList = []
		if "," in filterText:
			split1 = filterText.split(",")
			for s in split1:
				filterTextList.append(s)
		else:
			filterTextList.append(filterText)
			
		curList = []
		for item in self.listbox.get(0, tk.END):
			for filt in filterTextList:
				if filt.lower() in item[1].lower():
					curList.append(item)
				elif filt == item[0]:
					curList.append(item)
					
		return curList
		
	def enterCallback(self, event=None):
		filterText = self.contents.get()
		
		#reset filter
		if len(filterText) < 1:
			self.listbox.delete(0, tk.END)
			
			for item in self.listcontent:
				self.listbox.insert(tk.END, item)

			self.label.config(text=str(len(self.listbox.get(0, tk.END))))
			return
		
		curList = self.filter(filterText)

		self.listbox.delete(0, tk.END)
		for item in curList:
			self.listbox.insert(tk.END, item)
		self.label.config(text=str(len(self.listbox.get(0, tk.END))))

	def buttonCallback(self):
		#for i in self.listbox.curselection():
		for i in self.listbox2.get(0, tk.END):
			self.selected.append(i)
		self.master.destroy()
		
	def addButtonCallback(self):
		for i in self.listbox.curselection():
			tempItems = self.listbox2.get(0, tk.END)
			if self.listbox.get(i) not in tempItems:
				self.listbox2.insert(tk.END, self.listbox.get(i))				
		self.label2.config(text=str(len(self.listbox2.get(0, tk.END))))
		
	def removeButtonCallback(self):
		indexes = self.listbox2.curselection()
		indexes = indexes[::-1]
		for i in indexes:
			self.listbox2.delete(i)
		self.label2.config(text=str(len(self.listbox2.get(0, tk.END))))
		
	def getSelected(self):
		self.master.wm_deiconify()
		self.entry.focus_force()
		self.master.wait_window()
		return self.selected
		
def getPromptUser(prompt="", title=""):
	root = tk.Tk()
	root.withdraw()
	data = DialogPrompt(root, prompt, title).show()
	root.destroy()
	root.mainloop()
	
	return data
	
def NotifyBox(prompt=""):
	root = tk.Tk()
	root.withdraw()
	data = MessageBox(root, prompt).show()
	root.destroy()
	root.mainloop()

def getSelectedPlugins():
	global uniquePlugins

	root = tk.Tk()
	app = PluginSelector(root, list(uniquePlugins))
	app.master.title("Plugin Selector")
	try:
		app.master.iconbitmap('logo_icon_16x16.ico')
	except:
		pass
	data = app.getSelected()
	root.mainloop()
	
	return data
		
########################################
#Nessus Plugin parsers
########################################

def handleGenericPlugin(pluginId, pluginName, port, data):
	global pluginInfo
	
	if (pluginId,pluginName) in pluginInfo:
		pluginInfo[(pluginId,pluginName)][0].append(port)
		pluginInfo[(pluginId,pluginName)][1].append(data)
	else:
		pluginInfo[(pluginId,pluginName)] = ([],[])
		pluginInfo[(pluginId,pluginName)][0].append(port)
		pluginInfo[(pluginId,pluginName)][1].append(data)

def parsePlugin55472(value): #Device Hostname
	hostname = ""
	
	valParts = value.split("\n")
	for parts in valParts:
		if "Hostname" in parts:
			splStr = parts.split(":")
			if len(splStr) > 1:
				fqdn = splStr[1].strip()
				hostnameParts = fqdn.split(".")
				if len(hostnameParts) > 0:
					hostname = hostnameParts[0]
			break
				
	return hostname

#TODO update
def parsePlugin12053(value): #Host Fully Qualified Domain Name (FQDN) Resolution
	hostname = ""

	valParts = value.split(" ")
	if len(valParts) > 1:
		part = valParts[len(valParts)-1]
		hostnameParts = part.split(".")
		if len(hostnameParts) > 0:
			hostname = hostnameParts[0]
	
	return hostname

def parsePlugin10719(value): #MSSql
	dataArr = data.split('|')
	if len(dataArr) > 2:
		type = dataArr[1].split(':')[1].strip()
		serviceInst.setBanner(type)
		
		#Add data
		data = dataArr[2:]
		serviceInst.note += "\n".join(data)
	return
	
def parsePlugin72684(value): #Enumerate Local Users (windows)
	userAccounts = []
	lines = value.split("\n")
	for line in lines:
		if "Name" in line:
			split1 = line.split(":")
			if len(split1) > 1:
				userAccounts.append(split1[1].strip())
				
	return userAccounts

def parsePlugin10399_10860(value): #SMB Use Domain SID to Enumerate Users, SMB Use Host SID to Enumerate Local Users
	userAccounts = []
	lines = value.split("\n")
	for line in lines:
		if "id" in line:
			split1 = line.split(" ")
			if len(split1) > 3:
				userAccounts.append(split1[3].strip())
				
	return userAccounts

def parsePlugin25203(value): #Enumerate IPv4 Interfaces via SSH
	ipAddrs = []
	lines = value.split("\n")
	for line in lines:
		if "-" in line:
			split1 = line.split(" ")
			if len(split1) > 2:
				ipAddrs.append(split1[2].strip())
	
	return ipAddrs
	
def parsePlugin63061(data, serviceInst): #VMWare VCenter
	websrvTypeArr = data.split('|')
	if len(websrvTypeArr) > 2:
		type = websrvTypeArr[2].split(':')[1].strip()
		serviceInst.setBanner(type)
		
		#Add data
		data = websrvTypeArr[2:]
		serviceInst.note += "\n".join(data)
	return
	
def parsePlugin57396(data, serviceInst): #VMWare VSphere
	websrvTypeArr = data.split('|')
	if len(websrvTypeArr) > 2:
		type = websrvTypeArr[1].split(':')[1].strip()
		serviceInst.setBanner(type)
		
		#Add data
		data = websrvTypeArr[2:]
		serviceInst.note += "\n".join(data)
	return
	
def parsePlugin10107(data, serviceInst): #HTTP Server Type and Version
	websrvTypeArr = data.split('||')
	if len(websrvTypeArr) > 2:
		type = websrvTypeArr[1].split('|')[0]
		serviceInst.setBanner(type)
		
		#Add data
		data = websrvTypeArr[2:]
		serviceInst.note += "\n".join(data)
	return
	
def parsePlugin10144(data, serviceInst): #Microsoft SQL Server

	dataArr = data.split('|')
	if len(dataArr) > 3:
		type = "Microsoft SQL Server:"
		type += dataArr[1].replace("The remote SQL Server version is", "").strip()		
		serviceInst.setBanner(type)
			
	return

def parsePlugin10263(data, serviceInst): #SMTP Server Detection

	dataArr = data.split('||')
	if len(dataArr) > 3:
		type = dataArr[3]
		serviceInst.setBanner(type)
			
	return
	
def parsePlugin24260(data, serviceInst): #HTTP Server Type and Version
	webDataArr = data.split('|')
	for line in webDataArr:
		if "Server:" in line:
			lineArr = line.split(":")
			if len(lineArr) > 1:
				srvName = lineArr[1].strip()
				serviceInst.setBanner(srvName)
		elif "X-Powered-By:" in line:
			lineArr = line.split(":")
			if len(lineArr) > 1:
				appName = lineArr[1].strip()
				prop = EntityProperty("webapp.name","Web Application Name",appName)
				serviceInst.addCustomProperty(prop)
			
	#Add data
	serviceInst.note += data.replace('|', '\n') + '\n'
	
	return
	
def parsePlugin10267(data, serviceInst): #SSH Server Type and Version
	dataArr = data.split('|')
	if len(dataArr) > 1:
		version = dataArr[1].split(':')[1].strip()
		serviceInst.setBanner(version)
	return
	
def parseGenericSSH(data, serviceInst): #SSH Other
	
	if serviceInst.banner == '':
		serviceInst.setBanner('SSH')
		
	serviceInst.note += data.replace('|', '\n')
	
def parseGenericServicePlugin(data, serviceInst): #Generic Service Plugin
			
	#sanatize totalstr so it doesnt interfere with xml
	#tupleList = [("<","("),(">",")"),("|","\n"),("&","&amp;")]
	#totalstr = sanitize(data, tupleList)

	#serviceInst.note += totalstr + "\n"
	serviceInst.note += data + "\n"
	
def parsePlugin95928(value): #Linux User List Enumeration
	userAccounts = []
	lines = value.split("\n")
	beforeSystemAccounts = True
	for line in lines:
		if "System Accounts" in line:
			beforeSystemAccounts = False
			break
			
		if beforeSystemAccounts is True:
			if "User" in line:
				userLine = line.split(":")
				if len(userLine) > 1:
					userAccounts.append(userLine[1].strip())
		
	return userAccounts

def parsePlugin11936(value, entInst): #OS Identification
	lines = value.split("\n")
	for line in lines:
		if "Remote operating system" in line:
			split1 = line.split(":")
			if len(split1) > 1:
				os = split1[1][1:]
				prop = EntityProperty("dnsname.os","Operating System",os)
				entInst.addCustomProperty(prop)
			break

def parsePlugin35371(value, serviceInst): #DNS banner and hostname
	
	if serviceInst == None:
		valParts = value.split("\n")
		if len(valParts) > 3:
			part = valParts[3]
			hostnameParts = part.split(".")
			if len(hostnameParts) > 0:
				hostname = hostnameParts[0]	
				return hostname
	else:
		if serviceInst.banner == '':
			serviceInst.setBanner('DNS')
		
def parsePlugin54615(value, entInst): #Device type
	lines = value.split("\n")
	for line in lines:
		if "Remote device type" in line:
			split1 = line.split(":")
			if len(split1) > 1:
				devicetype = split1[1][1:]
				prop = EntityProperty("dnsname.devicetype","Device Type",devicetype)
				entInst.addCustomProperty(prop)
			break

def parsePlugin10908(value): #Microsoft Windows 'Domain Administrators' Group User List
	userAccounts = []
	lines = value.split("\n")
	for line in lines:
		if "-" in line:
			split1 = line.split(" ")
			if len(split1) > 3:
				userAccounts.append(split1[3])
				
	return userAccounts

def parsePlugin10902(value): #Microsoft Windows 'Administrators' Group User List
	userAccounts = []
	lines = value.split("\n")
	for line in lines:
		if "-" in line:
			split1 = line.split(" ")
			if len(split1) > 3:
				split2 = split1[3].split("\\")
				if len(split2) > 1:
					userAccounts.append(split2[1])
					
	return userAccounts

		
########################################
#Nessus Scan functions (Policy)
########################################
		
def handlePluginSet(value):
	global uniquePluginIds
	
	pluginIds = value.text.split(";")
	for pluginId in pluginIds:
		uniquePluginIds.add(pluginId)
		
def handlePolicyServerPreferences(ServerPreferencesElement):
	name = None
	value = None
	
	for preference in ServerPreferencesElement:
		name = preference.find("name")
		value = preference.find("value")

		if (name is not None) and (value is not None):
			if name.text == "plugin_set":
				handlePluginSet(value)
	
def handlePolicyPreferences(PolicyPreferencesElement):
	for child in PolicyPreferencesElement:
		if child.tag == "ServerPreferences":
			handlePolicyServerPreferences(child)
		elif child.tag == "PluginsPreferences":
			pass
		
def handlePolicy(PolicyElement, mode=STATMODE):
	for child in PolicyElement:
		if child.tag == "policyName":
			pass
		elif child.tag == "Preferences":
			#handlePolicyPreferences(child)
			pass
		elif child.tag == "FamilySelection":
			pass
		elif child.tag == "IndividualPluginSelection":
			pass


########################################
#Nessus Scan functions (Report)
########################################

def handleReportItem(ReportItemElement, mode=STATMODE, entityInst=None):
	global pluginIncludeList
	global uniquePlugins
	global badXML
	
	if mode == GATHERPLUGINMODE:
		pluginId = ReportItemElement.get("pluginID")
		pluginName = ReportItemElement.get("pluginName")
		uniquePlugins.add((pluginId, pluginName))
		
	elif mode == IPENTITYMODE:
		pluginId = ReportItemElement.get("pluginID")
		hostname = ""
		data = ""
		for child in ReportItemElement:
			if child.tag == "plugin_output":
				data = sanitize(child.text, badXML)
				
		if pluginId is not None:
			if pluginId == "55472":
				hostname = parsePlugin55472(data)
			elif pluginId == "12053":
				hostname = parsePlugin12053(data)
			elif pluginId == "35371":
				hostname = parsePlugin35371(data, None)
			elif pluginId == "11936":
				parsePlugin11936(data, entityInst)						
			elif pluginId == "54615":
				parsePlugin54615(data, entityInst)
				
		if len(hostname) > 0:
			hostname = hostname.upper()
			entityInst.hostname = hostname
				
	elif mode == PLUGINENTITYMODE:
		pluginId = ReportItemElement.get("pluginID")
		if pluginId is not None:
			if pluginId in pluginIncludeList:
				pluginName = ReportItemElement.get("pluginName")
				port = ReportItemElement.get("port")
				data = ""
				for child in ReportItemElement:
					if child.tag == "plugin_output":
						data = sanitize(child.text, badXML)
				
				#plugin parsing
				if pluginId == "11219": #Nessus SYN scanner
						
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					
				elif pluginId == "10107": #HTTP Server Type and Version
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin10107(data, serviceInst)
					
				elif pluginId == "35371" or pluginId == "11002": #DNS Banner
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin35371(data, serviceInst)
					
				elif pluginId == "10267": #SSH Server Type and Version
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin10267(data, serviceInst)
					
				elif pluginId == "10144": #Microsoft SQL Server 
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin10144(data, serviceInst)	
					
				elif pluginId == "10263": #SMTP Server Detection
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
						
					parsePlugin10263(data, serviceInst)
					
				elif pluginId == "63061": #VMware vCenter
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
						
					parsePlugin63061(data, serviceInst)
					
				elif pluginId == "57396": #VMware vSphere
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin57396(data, serviceInst)
																	
				elif pluginId == "10719": #MSSQL Banner
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin10719(data, serviceInst)	
					
				elif pluginId == "24260": #HTTP Information
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
					parsePlugin24260(data, serviceInst)
					
				elif pluginId == "70657" or pluginId == "10881": #SSH Other
				
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
						
					parseGenericSSH(data, serviceInst)
					
				elif pluginId == "22964" or pluginId == "51192" \
				  or pluginId == "70544" or pluginId == "57041" or pluginId == "21643" \
				  or pluginId == "10863" or pluginId == "56984" or pluginId == "87242" \
				  or pluginId == "42822" or pluginId == "11011" or pluginId == "34252" \
				  or pluginId == "21186" or pluginId == "10092" or pluginId == "31411" \
				  or pluginId == "20285" or pluginId == "17975" or pluginId == "11153" \
				  or pluginId == "10144" or pluginId == "22073" or pluginId == "26024" \
				  or pluginId == "20301" \
				  or pluginId == "11154": #Unknown Banner
				  #or pluginId == "77477" or pluginId == "102274"\ #SMB
				  #or pluginId == "100574" or pluginId == "20811" or pluginId == "72879"\ #SMB
				  #or pluginId == "44401" or pluginId == "38689" or pluginId == "100871"\ #SMB
				  #or pluginId == "10456" or pluginId == "10395" or pluginId == "58181"\ #SMB
				  
				  #Generic plugins
				  
					#See if service exists. if it doesn't, create it
					if port in serviceMap:
						serviceInst = serviceMap[port]
					else:
						serviceInst = Service(port, "")
						serviceMap[port] = serviceInst
						
					parseGenericServicePlugin(data, serviceInst)
					
				elif pluginId == "72684": #Enumerate Local Users (windows)
					retAccounts = parsePlugin72684(data)
					for account in retAccounts:
						userAccounts.append(Alias(account))
				elif pluginId == "10399" or pluginId == "10860": #SMB Use Domain SID to Enumerate Users, SMB Use Host SID to Enumerate Local Users
					retAccounts = parsePlugin10399_10860(data)
					for account in retAccounts:
						userAccounts.append(Alias(account))
				elif pluginId == "95928": #Linux User List Enumeration
					retAccounts = parsePlugin95928(data)
					for account in retAccounts:
						userAccounts.append(Alias(account))
				elif pluginId == "10908": #Microsoft Windows 'Domain Administrators' Group User List
					retAccounts = parsePlugin10908(data)
					for account in retAccounts:
						userAccounts.append(Alias(account,da=True))
				elif pluginId == "10902": #Microsoft Windows 'Administrators' Group User List
					retAccounts = parsePlugin10902(data)
					for account in retAccounts:
						userAccounts.append(Alias(account,la=True))
				else: #no special handler for plugin
					handleGenericPlugin(pluginId, pluginName, port, data)

def handleReportHost(ReportHostElement, mode=STATMODE, ipList=[]):
	global uniqueHosts
	global allHosts
	
	name = ReportHostElement.get("name")
	if name is not None:
		
		#stat collection mode
		if mode == STATMODE:
			uniqueHosts.add(name)
		
		#entity parsing mode
		elif mode == IPENTITYMODE:
			hostInst = None
			if len(ipList) > 0:
				if name in ipList:
					#Create IPv4Address objects for all report hosts
					hostInst = IPv4Address(name)
					#TODO parse tags
			else:
				#Create IPv4Address objects for all report hosts
				hostInst = IPv4Address(name)
				#TODO parse tags
				
			if hostInst is not None:
				for child in ReportHostElement:
					if child.tag == "ReportItem":
						handleReportItem(child, mode, hostInst)
				allHosts.append(hostInst)
						
		elif mode == PLUGINENTITYMODE:
			if name in ipList:
				for child in ReportHostElement:
					if child.tag == "ReportItem":
						handleReportItem(child, mode, None)
		
		#plugin parsing mode
		elif mode == GATHERPLUGINMODE:
			for child in ReportHostElement:
				if child.tag == "ReportItem":
					handleReportItem(child, mode)
		
def handleReport(ReportElement, mode=STATMODE, ipList=[]):
	for child in ReportElement:
		if child.tag == "ReportHost":
			handleReportHost(child, mode, ipList)

########################################
#Nessus Scan functions
########################################
			
def handleRoot(root, mode=STATMODE, ipList=[]):
	for child in root:
		if child.tag == "Policy":
			handlePolicy(child, mode)
		elif child.tag == "Report":
			handleReport(child, mode, ipList)

def parseNessus(nessusFiles=[], mode=STATMODE, ipList=[]):
	for nessusFile in nessusFiles:
		try:
			tree = ET.parse(nessusFile)
			root = tree.getroot()

			if root.tag == "NessusClientData_v2":
				handleRoot(root, mode, ipList)
		except Exception as ex:
			print ex

########################################
#Maltego Entity Handler functions
########################################

def handleIpEntity(entityValue="", properties=""):
	global pluginInfo
	global serviceMap
	global userAccounts
	global pluginIncludeList
	
	includeList = []
	ip = ""
	fileStr = None
	host = ""
	nessusFiles = []

	#parse calling entity properties
	ipprops = properties.split("#")
	for prop in ipprops:
		if "fqdn" in prop:
			fqdnProp = prop.split("=")
			if len(fqdnProp) > 1:
				host = fqdnProp[1]
		#if "ipv4-address" in prop:
		#	ipProp = prop.split("=")
		#	if len(ipProp) > 1:
		#		ip = ipProp[1]
		if NESSUSSCANPATHPROP in prop:
			nessusProp = prop.split("=")
			if len(nessusProp) > 1:
				fileStr = sanitize(nessusProp[1], [("\\\\","\\")])
		if "includelist" in prop:
			includeListProp = prop.split("=")
			if len(includeListProp) > 1:
				pluginIncludeList = eval(includeListProp[1])
	
	#prompt user for nessus files if not already specified
	fileStr, nessusFiles = getNessusScanFiles(fileStr)
	
	parseNessus(nessusFiles, PLUGINENTITYMODE, [entityValue])

	#start creation of Maltego message
	MaltegoMessage = MaltegoTransform()
	
	#ensure properties of calling entity updated
	#ent = MaltegoMessage.addEntity("maltego.IPv4Address", entityValue)
	#TODO update props
	
	#handle all plugins
	for key,value in pluginInfo.iteritems():
		
		totalstr = ""
		for val in value[1]:
			totalstr = totalstr + val
		portStr = str(value[0])
		
		if len(totalstr) > 2:
			#numEntities = numEntities + 1
			ent = MaltegoMessage.addEntity("securifera.NessusPlugin", key[1]+" ("+host+")")
			ent.addProperty(fieldName="pluginid",displayName="PluginID",value=key[0])
			ent.addProperty(fieldName="ports",displayName="Ports",value=portStr)
			ent.setNote(totalstr)
			
	#handle all open ports
	for port, service_inst in serviceMap.iteritems():
		service_inst.addEntity(MaltegoMessage)
		
	#handle all accounts
	for accountInst in userAccounts:
		accountInst.addEntity(MaltegoMessage)
	
	xmlStr = MaltegoMessage.returnOutput()
			
	return xmlStr

def handleNetblockEntity(entityValue="", properties=""):
	global allHosts
	global pluginIncludeList
	
	nessusFiles = []
	pluginfilter = ""
	fileStr = None
	
	#parse calling entity properties
	netblockProps = properties.split("#")
	for prop in netblockProps:
		#if "ipv4-range" in prop:
		#	ipProp = prop.split("=")
		#	if len(ipProp) > 1:
		#		ip = ipProp[1]
		if NESSUSSCANPATHPROP in prop:
			nessusScansDirProp = prop.split("=")
			if len(nessusScansDirProp) > 1:
				fileStr = sanitize(nessusScansDirProp[1], [("\\\\","\\")])
		if "pluginfilter" in prop:
			pluginFilterProp = prop.split("=")
			if len(pluginFilterProp) > 1:
				pluginfilter = pluginFilterProp[1]
				
	#prompt user for nessus files if not already specified
	fileStr, nessusFiles = getNessusScanFiles(fileStr)
	
	#prompt user for user for plugin selections
	if len(pluginfilter) < 1:
		parseNessus(nessusFiles, GATHERPLUGINMODE)
		data = getSelectedPlugins()

		for plugin in data:
			pluginIncludeList.append(plugin[0])
	else:
		pluginIncludeList = eval(pluginfilter)
				
	#make sure netblock has valid IP address range
	ipList = []
	try:
		if "-" in entityValue:
			ipArr = entityValue.split("-")
			if len(ipArr) > 1:
				startIp = ipArr[0]
				endIp = ipArr[1]
				#Check that each IP is made up of 4 numbers between 0-255
				ipQuad1 = startIp.split(".")
				for numStr in ipQuad1:
					num = int(numStr)
					if num < 0 or num > 255:
						raise Exception("IP Address provided is not in proper format: " + startIp )
				ipQuad2 = endIp.split(".")
				for numStr in ipQuad2:
					num = int(numStr)
					if num < 0 or num > 255:
						raise Exception("IP Address provided is not in proper format: " + endIp )				
						
				for q1 in range( int(ipQuad1[0]), int(ipQuad2[0]) + 1):
					for q2 in range( int(ipQuad1[1]), int(ipQuad2[1]) + 1):
						for q3 in range( int(ipQuad1[2]), int(ipQuad2[2]) + 1):
							for q4 in range( int(ipQuad1[3]), int(ipQuad2[3]) + 1):
								ipList.append( str(q1) + "." + str(q2) + "." + str(q3) + "." + str(q4) )
												
			
		elif "/" in entityValue:
			subnet = ipaddress.ip_network(unicode(entityValue))
			iprange = subnet.hosts()
			for ipObj in iprange:
				ipList.append(str(ipObj))
				
	except Exception, e:
		print "[-] Unable to parse netblock format: " + str(e)
		sys.exit(1)
		
	#start creation of Maltego message
	MaltegoMessage = MaltegoTransform()
	
	#ensure properties of calling entity updated
	ent = MaltegoMessage.addEntity("maltego.Netblock", entityValue)
	ent.addProperty(NESSUSSCANPATHPROP, NESSUSSCANPATHPROPDIS, value=fileStr)
	ent.addProperty("pluginfilter", "PluginFilter", value=str(pluginIncludeList))
	
	#parse files for IPv4Address entity creation
	parseNessus(nessusFiles, IPENTITYMODE, ipList)
	for host in allHosts:
		host.addCustomProperty(EntityProperty(NESSUSSCANPATHPROP,"NessusPath",fileStr))
		host.addCustomProperty(EntityProperty("includelist","IncludeList",str(pluginIncludeList)))
		host.addEntity(MaltegoMessage)
	
	xmlStr = MaltegoMessage.returnOutput()
			
	return xmlStr
	
def handleNessusScanEntity(entityValue="", properties=""):
	global allHosts
	global pluginIncludeList
	
	nessusFiles = []
	pluginfilter = ""
	fileStr = None
	
	#parse calling entity properties
	nessusScanProps = properties.split("#")
	for prop in nessusScanProps:
		if NESSUSSCANPATHPROP in prop:
			nessusScansDirProp = prop.split("=")
			if len(nessusScansDirProp) > 1:
				fileStr = sanitize(nessusScansDirProp[1], [("\\\\","\\")])
		if "pluginfilter" in prop:
			pluginFilterProp = prop.split("=")
			if len(pluginFilterProp) > 1:
				pluginfilter = pluginFilterProp[1]
	
	#prompt user for nessus files if not already specified
	fileStr, nessusFiles = getNessusScanFiles(fileStr)
	
	#prompt user for user for plugin selections
	if len(pluginfilter) < 1:
		parseNessus(nessusFiles, GATHERPLUGINMODE)
		data = getSelectedPlugins()

		for plugin in data:
			pluginIncludeList.append(plugin[0])
	else:
		pluginIncludeList = eval(pluginfilter)

	#start creation of Maltego message
	MaltegoMessage = MaltegoTransform()
	
	#ensure properties of calling entity updated
	ent = MaltegoMessage.addEntity("securifera.NessusScan", entityValue)
	ent.addProperty(NESSUSSCANPATHPROP, NESSUSSCANPATHPROPDIS, value=fileStr)
	ent.addProperty("pluginfilter", "PluginFilter", value=str(pluginIncludeList))
	
	#parse files for IPv4Address entity creation
	parseNessus(nessusFiles, IPENTITYMODE)
	for host in allHosts:
		host.addCustomProperty(EntityProperty(NESSUSSCANPATHPROP,"NessusPath",fileStr))
		host.addCustomProperty(EntityProperty("includelist","IncludeList",str(pluginIncludeList)))
		host.addEntity(MaltegoMessage)
	
	xmlStr = MaltegoMessage.returnOutput()
			
	return xmlStr	
			
def nessusScanStat(filePaths=[]):
	global uniqueHosts
	global uniquePlugins

	parseNessus(filePaths, GATHERPLUGINMODE)
	parseNessus(filePaths, STATMODE)
	
	print "Unique Plugins:", len(uniquePlugins)
	print "Unique Hosts:", len(uniqueHosts)
	
def usage():
	print "\nUsage:"
	print "\tpython nessusParser.py stat ['dir or file path']"
	print "\t  or"
	print "\tpython nessusParser.py EntityValue PropName#PropValue[,PropName#PropValue...]"

def main():
	
	#parse input
	#print len(sys.argv), sys.argv
	if len(sys.argv) < 2:
		print "Number of arguments is:", len(sys.argv), ". Expecting more"
		#print sys.argv
		usage()
		sys.exit(1)
		
	#stat as first argument signals not running from Maltego context
	if len(sys.argv) > 1 and "stat" == sys.argv[1]:
		print "Stats on Nessus scan data"
		startTime = time.time()
		if len(sys.argv) > 2:
			fileStr = sys.argv[2]
		else:
			fileStr = None
		
		fileStr, filePaths = getNessusScanFiles(fileStr)
		
		nessusScanStat(filePaths)
		endTime = time.time()
		print "Time elapsed:", endTime-startTime
		sys.exit(0)
	
	#Maltego context here
	if len(sys.argv) < 3:
		print "Number of arguments is:", len(sys.argv), ". Expecting more"
		print sys.argv
		sys.exit(1)
	
	entityValue = sys.argv[1]
	properties = sys.argv[2]
	
	#determine calling entity context
	xmlStr = ""
	if "ipv4-address" in properties:
		xmlStr = handleIpEntity(entityValue, properties)
	elif "ipv4-range" in properties:
		xmlStr = handleNetblockEntity(entityValue, properties)
	elif NESSUSSCANPROP in properties:
		xmlStr = handleNessusScanEntity(entityValue, properties)
	else:
		print "Unknown calling entity:", entityValue, properties
		sys.exit(1)

	#output xml
	print xmlStr
	
if __name__ == "__main__":
	main()