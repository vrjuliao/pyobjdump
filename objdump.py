import capstone as cp
from elftools.elf.elffile import ELFFile
import bisect
from diffObjdump import FunctionFeatures

class Objdump:
  __local_code_begin = 0
  __local_code_end = 0
  __linked_code_begin = 0
  __linked_code_end = 0

  def __init__(self, filename):
    self.__name = filename
    with open(filename, 'rb') as f:
      self.__elf = ELFFile(f)
      self.__mount_symbols_list()
      self.__parse_local_functions()

  @property
  def name(self):
    return self.__name

  def __mount_symbols_list(self):
    # getting .text section bounds
    dot_text_section = self.__elf.get_section_by_name('.text')
    self.__local_code_begin = dot_text_section['sh_addr']
    self.__local_code_end = self.__local_code_begin + dot_text_section.data_size

    # getting .plt (procedure linkage table) section bounds
    dot_plt_section = self.__elf.get_section_by_name('.plt')
    self.__linked_code_begin = dot_plt_section['sh_addr']
    self.__linked_code_end = self.__linked_code_begin + dot_plt_section.data_size

    # stores all local function names
    self.__local_symbols = dict()

    # stores a pair containing the start address of a function and the function
    # name, like (addr, func_name)
    local_symbols_address = list()
    self.__global_symbols_address = list()

    # Storing function names
    # TODO: Instead of using string types to access the dictionaries,
    #       use a constant or something to avoid Magic Values
    #       Unfortunatelly it is a limitation of pyelftools library
    local_symtab = self.__elf.get_section_by_name('.symtab')
    for _, sym in enumerate(local_symtab.iter_symbols()):
      addr = sym.entry['st_value']
      # Ensures that it is getting only functions that have its body inside
      # '.text' section at the ELF file
      if(sym.entry['st_info']['type'] == 'STT_FUNC'
      and self.__is_local_code(addr)):
        self.__local_symbols[sym.name] = []
        local_symbols_address.append((addr, sym.name))
    
    global_symtab = self.__elf.get_section_by_name('.dynsym')
    for _, sym in enumerate(global_symtab.iter_symbols()):
      addr = sym.entry['st_value']
      if(sym.entry['st_info']['type'] == 'STT_FUNC'):
        # Ensures that it is getting only functions that have its body inside
        # '.plt' section at the ELF file
        if(self.__is_linked_code(addr)):
          self.__global_symbols_address.append((addr, sym.name))
        
        # Ensures that it is getting only functions that have its body inside
        # '.text' section at the ELF file
        elif(self.__is_local_code(addr)):
          self.__local_symbols[sym.name] = []
          local_symbols_address.append((addr, sym.name))
    
    # This attribute will be used to identify when some funcion is called.
    # We are savind it previouly sorted to use a binary search to query which
    # function is being called via its address.
    self.__global_symbols_address.sort()
    local_symbols_address.sort()

    # some functions are declared in both scopes: .plt and .text, so we are
    # removing that duplication
    self.__local_symbols_address = self.__remove_local_address_duplications(local_symbols_address)
  
  def __is_linked_code(self, address):
    return (address >= self.__linked_code_begin
      and address < self.__linked_code_end)
  
  def __is_local_code(self, address):
    return (address >= self.__local_code_begin
      and address < self.__local_code_end)

  def __remove_local_address_duplications(self, local_symbols):
    num_of_functions = len(local_symbols)
    result = list()
    for i in range(num_of_functions-1):
      if(local_symbols[i][0] != local_symbols[i+1][0]):
        result.append(local_symbols[i])
    
    if(num_of_functions > 1 and local_symbols[-2][0] != local_symbols[-1][0]):
      result.append(local_symbols[-1])

    return result        

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

    func_index = 0
    for ins in md.disasm(asm_code, start_header_addr): 
      # validating if the current address (ins.address) corresponds to
      # the next function in the self.__local_symbols_address list
      if(func_index < len(self.__local_symbols_address)-1 and
        ins.address >= self.__local_symbols_address[func_index+1][0]):
        func_index += 1
      func_name = self.__local_symbols_address[func_index][1]
      self.__local_symbols[func_name].append(ins)

  def get_function_name_by_address(self, address):
    # binary search to get which function {address} corresponds to.
    if(self.__is_local_code(address) and len(self.__local_symbols_address) > 0):
      idx = bisect.bisect_left(self.__local_symbols_address, (address, ""))
      if(address < self.__local_symbols_address[idx][0]):
        idx -= 1
      if(idx < 0):
        return None
      return self.__local_symbols_address[idx][1]
    elif (self.__is_linked_code(address) and len(self.__global_symbols_address) > 0):
      idx = bisect.bisect_left(self.__global_symbols_address, (address, ""))
      if(address < self.__global_symbols_address[idx][0]):
        idx -= 1
      if(idx < 0):
        return None
      return self.__global_symbols_address[idx][1]
    else:
      return None

  def get_function_names(self):
    return self.__local_symbols.keys()

  def get_function_instructions(self, func_name):
    if func_name in self.__local_symbols:
      return self.__local_symbols[func_name]
    return []

  # for debugging purposes
  def print_instructions(self):
    for (_, name) in self.__local_symbols_address:
      print(FunctionFeatures(name, self))