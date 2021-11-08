import capstone

class FunctionFeatures:
  name: str
  num_of_instructions: int
  num_of_memory_access: int
  num_of_possible_branches: int
  call_instructions: dict # function_name -> number_of_calls

  def __init__(self, name, dumpedobj):
    self.__instructions_list = dumpedobj.get_function_instructions(name)
    self.name = name
    self.num_of_instructions = len(self.__instructions_list)
    self.num_of_memory_access = 0
    self.num_of_possible_branches = 0
    self.call_instructions = {}
    self.__compute_instructions(dumpedobj)

  def __is_branch_inst(self, instruction_groups):
    if(capstone.x86.X86_GRP_JUMP in instruction_groups
    or capstone.x86.X86_GRP_CALL in instruction_groups
    or capstone.x86.X86_GRP_BRANCH_RELATIVE in instruction_groups
    or capstone.x86.X86_GRP_RET in instruction_groups):
      return True
    return False

  def __get_immediate_operator_values(self, operands):
    result = []
    for op in operands:
      if(op.type == capstone.x86.X86_OP_IMM):
        result.append(op.value.imm)
    return result

  def __compute_memory_access(self, operands):
    for op in operands:
      if(op.type == capstone.x86.X86_OP_MEM):
        self.num_of_memory_access += 1

  def __compute_instructions(self, dumpedobj):
    for ins in self.__instructions_list:
      # return a boolean informing if this instruction is a branch_type or not
      branch_instruction = self.__is_branch_inst(ins.groups)
      if(branch_instruction):
        self.num_of_possible_branches += 1
      
        # return a list with the immediate values
        immediate_values = self.__get_immediate_operator_values(ins.operands)
        for imm_value in immediate_values:
          func_name = dumpedobj.get_function_name_by_address(address=imm_value)
          if (func_name is not None and func_name != self.name):
            if(func_name in self.call_instructions):
              self.call_instructions[func_name] += 1
            else:
              self.call_instructions[func_name] = 1

      # increases the value of num_of_memory_access when the instruction has memory operators
      self.__compute_memory_access(ins.operands)

  def __str__(self):
    return "<%s>"%(self.name) +\
          "\n\tFunc calls: " + str(self.call_instructions.keys()) +\
          "\n\tMemory access: " + str(self.num_of_memory_access) +\
          "\n\tPossible branches: " + str(self.num_of_possible_branches) +\
          "\n\tInstructions qtt " + str(self.num_of_instructions)

class DiffObjdump:
  def __init__(self, dump1, dump2):
    self.__dump1 = dump1
    self.__dump2 = dump2

  def diff_report(self):
    # Get {dump1} and {dump2} function names and store it in a set,
    # after generate the stats for those functions, remove its names from the set.
    # The remainig elements are those that match only in one dump.
    d1_func_names = set(self.__dump1.get_function_names())
    d2_func_names = set(self.__dump2.get_function_names())

    # for each function_name in {dump1}, generate function stats:
    # called functions and the respectice count, memory access count, branches count
    for func_name in d1_func_names:
      # func1_features = FunctionFeatures(func_name, self.__dump1)
      func1_features = FunctionFeatures('frame_dummy', self.__dump1)
      return
      # check if {dump2} also have such function name:
      if(func_name in d2_func_names):
        # if so: compute stats and compare one by one with the {dump1} stats
        func2_features = FunctionFeatures(self.__dump2, func_name)
        d1_func_names.remove(func_name)
        d2_func_names.remove(func_name)
        self.__report_comparison_between_features(func1_features, func2_features)
      else:
      # else: print a report informing that {dump2} does not have such function, and print {dump1} stats
        self.__report_features(func1_features, 1)
        self.__report_inexistant_function(func_name, 2)

    # for the remaining function names in the set of {dump2}, report that {dump1} does not have such function
    # and print this function information
    for func_name in d2_func_names:
      func_features = FunctionFeatures(func_name, self.__dump2)
      self.__report_inexistant_function(func_name, 1)
      self.__report_features(func_features, 2)
