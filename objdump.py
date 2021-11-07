import capstone as cp
from elftools.elf.elffile import ELFFile

class Objdump:
  def __init__(self, filename):
    with open(filename, 'rb') as f:
      self.__elf = ELFFile(f)
      self.__mount_symbols_list()
      self.__parse_local_functions()

  def __mount_symbols_list(self): 
    # stores all local function names
    self.__local_symbols = dict()

    # stores a pair containing the start address of a function and the function
    # name, like (addr, func_name)
    self.__local_symbols_address = list()
    self.__global_symbols_address = list()

    # Storing function names
    # TODO: Instead of using string types to access the dictionaries,
    #       use a constant or something to avoid Magic Values
    #       Unfortunatelly it is a limitation of pyelftools library
    local_symtab = self.__elf.get_section_by_name('.symtab')
    for _, sym in enumerate(local_symtab.iter_symbols()):
      if(sym.entry['st_info']['type'] == 'STT_FUNC'):
        self.__local_symbols[sym.name] = []
        self.__local_symbols_address.append((sym.entry['st_value'], sym.name))
    
    global_symtab = self.__elf.get_section_by_name('.dynsym')
    for _, sym in enumerate(global_symtab.iter_symbols()):
      if(sym.entry['st_info']['type'] == 'STT_FUNC'):
        self.__global_symbols_address.append((sym.entry['st_value'], sym.name))
    
    # This attribute will be used to identify when some funcion is called.
    # We are savind it previouly sorted to use a binary search to query which
    # function is being called via its address.
    sorted(self.__global_symbols_address)
    sorted(self.__local_symbols_address)
  
  def __parse_local_functions(self):
    code = self.__elf.get_section_by_name('.text')
    asm_code = code.data()
    start_header_addr = code['sh_addr']

    # The capstone Cs creation can be automated dinamically using the following methods and attributes:
      # self.__elf.get_machine_arch()
      # self.__elf.little_endian
      # self.__elf.elf_class -> to decide if it is 32 or 64 bits
    # Since we have a punctual sample, we state these attributes statically
    md = cp.Cs(cp.CS_ARCH_X86, cp.CS_MODE_64+cp.CS_MODE_LITTLE_ENDIAN)
    
    # With this property switched on, we will be able to obtain more information about each instrucion
    md.detail = True
    for ins in md.disasm(asm_code, start_header_addr):     
      print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')

import sys
Objdump(sys.argv[1])