import idc 
import idaapi
import idautils
import ctypes

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
        	# Compile the form once
        	if not self.Compiled():
            		_, args = self.Compile()
	        # Execute the form
        	ok = self.Execute()
		if (ok != 0):
			NClass = TClass(self.txtClassName.value, 
					self.iClassSize.value, 
					self.iVtableAddr.value)
			NClass.printdbg()
			NClass.create_struct()
		return ok
		
class vtable_helper(idaapi.plugin_t):
	flags = 0
	comment = "Plugin for creating and commenting automatically vtable stuff"
	help = "RTFC"
	wanted_name = "vtable_helper"
	wanted_hotkey = "Alt-F5"

	def init(self):
		return idaapi.PLUGIN_OK

	def run(self, args):
        	f = VtableHelperForm()
        	# Show the form
        	ok = f.Show()
        	if ok == 0:
            		f.Free()

	def term(self):
		pass

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
		self.struct = AddStrucEx(-1, self.name, 0) # index, name, is_union
		for i in xrange(0, self.size / 4):
			AddStrucMember(self.struct, "field_" + str(i), i * 4, FF_DWRD | FF_DATA, -1, 4)
		if (self.size % 4) != 0:
			AddStrucMember(self.struct, "field_" + str(self.size / 4), (self.size / 4) * 4, FF_DWRD | FF_DATA, -1, self.size % 4)

	def create_vtable(self):
		SetMemberName(self.struct, 0, "vptr") # Setup name of the first member

class vptr():
	def __init__(self, addr, size):
		self.addr = addr
		self.size = size

def PLUGIN_ENTRY():
	return vtable_helper()
