import idc 
import idaapi
import idautils

class rename_idp_hook_t(idaapi.IDP_Hooks):
	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)
		self.cmd = idaapi.cmd
	
	# http://code.google.com/p/idapython/source/browse/trunk/swig/idp.i?r=315#448
	# keyword "pass" is missing
	def custom_outop(self, op):
		pass

	# http://code.google.com/p/idapython/source/browse/trunk/swig/idp.i?r=315#459
	# keyword "pass" is missing
	def custom_mnem(self):
		pass

	def renamed(self, ea, name, local_name):
		print("Name %s" % name)


class VtableHelperForm(Form):
	def __init__(self):
		Form.__init__(self, r"""Vtable Helper
		<#Class Name :{txtClassName}>
		<#Class Size :{iClassSize}>
		<#Vtable Addr :{iVtableAddr}>

		""", {
		    	'txtClassName'	: 	Form.StringInput(),
			'iClassSize'	:	Form.NumericInput(),
			'iVtableAddr' 	:	Form.NumericInput(),
		})

	def OnFormChange(self, fid):
		return 1

	def Show(self):
        	if not self.Compiled():
            		_, args = self.Compile()
        	ok = self.Execute()
		if (ok != 0):
			NClass = TClass(self.txtClassName.value, 
					self.iClassSize.value, 
					self.iVtableAddr.value)
			NClass.printdbg()
			NClass.create_struct()
			NClass.create_vtable()
		return ok
		
class vtable_helper(idaapi.plugin_t):
	flags = 0
	comment = "Plugin for creating and commenting automatically vtable stuff"
	help = "RTFC"
	wanted_name = "vtable_helper"
	wanted_hotkey = "Alt-F5"

	def init(self):
		self.idphook = None
 		self.idphook = rename_idp_hook_t()
    		self.idphook.hook()
		return idaapi.PLUGIN_KEEP

	def run(self, args):
        	f = VtableHelperForm()
        	ok = f.Show()
        	if ok == 0:
            		f.Free()

	def term(self):
		if self.idphook:
			self.idphook.unhook()

class TClass():
	def __init__(self, name, size, addrvtable):
		self.name = name
		self.addr_vtable = addrvtable
		self.size = size
		self.vtable = {}

	def printdbg(self):
		print("ClassName : %s" % self.name)
		print("ClassSize : %X" % self.size)
		print("Addr_vtable : %X" % self.addr_vtable)

	def create_struct(self):
		if (self.size == 0):
			print("Invalid class size")
		struc_id = GetStrucIdByName(self.name)
		if (struc_id != -1):
			i = AskYN(0, "A class structure for %s already exists. Are you sur you want to remake it ?" % self.name)
			if (i == -1 or i == 0):
				self.struct = struc_id
				return
			DelStruc(struc_id)
		self.struct = AddStrucEx(-1, self.name, 0)
		for i in xrange(0, self.size / 4):
			AddStrucMember(self.struct, "field_" + str(i), i * 4, FF_DWRD | FF_DATA, -1, 4)
		if (self.size % 4) != 0:
			AddStrucMember(self.struct, "field_" + str(self.size / 4), (self.size / 4) * 4, FF_DATA, -1, self.size % 4)

	def create_vtable(self):
		SetMemberName(self.struct, 0, "vptr")

class vptr():
	def __init__(self, addr, size):
		self.addr = addr
		self.size = size

def PLUGIN_ENTRY():
	#hook_to_notification_point(HT_IDB, 0, 0)
	return vtable_helper()
