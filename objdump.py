import capstone
from elftools.elf.elffile import ELFFile

class Objdump:
  def __init__(self, filename):
    with open(filename, 'rb') as f:
      self.__elf = ELFFile(f)
      self.__mount_symbols_list()

  def __mount_symbols_list(self): 
    # stores all local function names
    self.__symbols = dict()
    # stores a pair containing the start addess of a function and the function
    # name, like (addr, func_name)
    self.__symbols_indexes = list()

    local_symtab = self.__elf.get_section_by_name('.symtab')
    for i, sym in enumerate(local_symtab.iter_symbols()):
      # TODO: Instead of using string types to access the dictionaries,
      #       use a constant or something to avoid Magic Values
      # symbol type
      self.__symbols[sym.name] = sym.entry['st_info']['type']
      self.__symbols_indexes.append((sym.entry['st_value'], sym.name))

    j = 0
    for (sym_name, sym_entry) in self.__symbols.items() :
      print("%s:"%sym_name, sym_entry)
      print()
      j+=1
      if(j>5): break

import sys
Objdump(sys.argv[1])