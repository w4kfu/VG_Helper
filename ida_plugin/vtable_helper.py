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
			'iClassSize'	:	Form.NumericInput(tp=Form.FT_RAWHEX),
			'iVtableAddr' 	:	Form.NumericInput(tp=Form.FT_ADDR),
		})

	def Show(self, cfg):
        	# Compile the form once
        	#if not self.Compiled():
            	_, args = self.Compile()

		# Remember the config
        	self.cfg = cfg

	        # Execute the form
        	ok = self.Execute()

        	# Forget the cfg
        	del self.cfg
		
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
		cfg = 0
        	# Show the form
        	ok = f.Show(cfg)
        	if ok == 0:
            		f.Free()

	def term(self):
		pass

class TClass():
	def __init__(self, name, addrvtable, size):
		self.name = name
		self.addr_vtable = addrvtable
		self.size = size
		self.vtable = {}
	def get_size(self):
		return self.size
	def get_addr(self):
		return self.addr_vtable
	def create_struct(self):
		self.struct = AddStructEx(-1, self.name, 0) # index, name, is_union
		for i in xrange(0, self.size):
			AddStrucMember(self.struct, "field_" + str(i), i * 4, FF_DWRD | FF_DATA, -1, 4)
	def create_vtable(self):
		SetMemberName(self.struct, 0, "vptr") # Setup name of the first member

class vptr():
	def __init__(self, addr, size):
		self.addr = addr
		self.size = size

def PLUGIN_ENTRY():
	return vtable_helper()
