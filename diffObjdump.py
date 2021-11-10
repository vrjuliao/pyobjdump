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
    # print(str(self))

  # for debugging purposes
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
      func1_features = FunctionFeatures(func_name, self.__dump1)
      # check if {dump2} also have such function name:
      if(func_name in d2_func_names):
        # if so: compute stats and compare one by one with the {dump1} stats
        func2_features = FunctionFeatures(func_name, self.__dump2)
        d2_func_names.remove(func_name)
        self.__report_comparison_between_features(func1_features, func2_features)
      else:
      # else: print a report informing that {dump2} does not have such function, and print {dump1} stats
        self.__report_function_in_only_one_scope(func1_features, 1)

    # for the remaining function names in the set of {dump2}, report that {dump1} does not have such function
    # and print this function information
    for func_name in d2_func_names:
      func_features = FunctionFeatures(func_name, self.__dump2.name)
      self.__report_function_in_only_one_scope(func_features, 1)


  def __report_function_in_only_one_scope(self, func_feature, function_scope_name):
    print("Function <{func_name}> report:".format(func_name=func_feature.name))
    print("\tIt is only present in {scope}".format(scope=function_scope_name))
    print("\t{property} instructions.".format(property=func_feature.num_of_instructions))
    print("\t{property} memory access.".format(property=func_feature.num_of_memory_access))
    print("\t{property} possible branches.".format(property=func_feature.num_of_possible_branches))
    print("\tHaving the following function calls:")
    for func_call in func_feature.call_instructions.keys():
      print("\t\t", func_call)

  # name: str
  # call_instructions: dict # function_name -> number_of_calls
  def __report_comparison_between_features(self, func_feature1, func_feature2):
    report_information = []
    if(func_feature1.num_of_instructions != func_feature2.num_of_instructions):
      report_information.append(
        "\tIn {obj1} it has {property1} instructions, whereas in {obj2} it has {property2}.".
          format(obj1=self.__dump1.name, property1=func_feature1.num_of_instructions,
                 obj2=self.__dump2.name, property2=func_feature2.num_of_instructions)
      )

    if(func_feature1.num_of_memory_access != func_feature2.num_of_memory_access):
      report_information.append(
        "\tIn {obj1} it has {property1} memory access, whereas in {obj2} it has {property2}.".
          format(obj1=self.__dump1.name, property1=func_feature1.num_of_memory_access,
                 obj2=self.__dump2.name, property2=func_feature2.num_of_memory_access)
      )

    if(func_feature1.num_of_possible_branches != func_feature2.num_of_possible_branches):
      report_information.append(
        "\tIn {obj1} it has {property1} possible branches, whereas in {obj2} it has {property2}.".
          format(obj1=self.__dump1.name, property1=func_feature1.num_of_possible_branches,
                 obj2=self.__dump2.name, property2=func_feature2.num_of_possible_branches)
      )

    func2_call_names = set(func_feature2.call_instructions.keys())
    for (call_name, call_qtt) in func_feature1.call_instructions.items():
      if(call_name in func_feature2.call_instructions):
        call_qtt2 = func_feature2.call_instructions[call_name]
        if(call_qtt != call_qtt2):
          report_information.append(
              "\tIn {obj1} it {call_name} has {property1} call(s), whereas in {obj2} it has {property2}.".
                format(obj1=self.__dump1.name, property1=func_feature1.num_of_possible_branches,
                       obj2=self.__dump2.name, property2=func_feature2.num_of_possible_branches,
                       call_name=call_name)
          )
        func2_call_names.remove(call_name)
      else:
        report_information.append(
        "\tFunction {call_name} is only called in {obj1}, but not in {obj2}.".
            format(obj1=self.__dump1.name, call_name=call_name, obj2=self.__dump2.name)
        )
        func_feature1.remove(call_name)
    
    for call_name in func2_call_names:
      report_information.append(
        "\tFunction {call_name} is only called in {obj1}, but not in {obj2}.".
            format(obj1=self.__dump2.name, call_name=call_name, obj2=self.__dump1.name)
        )

    if (len(report_information)>0):
      print("Function <{func_name}> report:".format(func_name=func_feature1.name))
      for ft in report_information:
        print(ft)
