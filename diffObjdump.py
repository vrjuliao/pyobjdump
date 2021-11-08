import capstone

class FunctionFeatures:
  name: str
  num_of_instructions: int
  num_of_memory_access: int
  call_instructions: dict # function_name -> number_of_calls

  def __init__(self, name, dumpedobj):
    self.__instructions_list = dumpedobj.get_function_instructions(name)
    self.name = name
    self.num_of_instructions = len(self.__instructions_list)
    self.num_of_memory_access = 0
    self.call_instructions = {}
    self.__compute_instructions()

  def __compute_instructions(self):
    for ins in self.__instructions_list:
      # return a boolean informing if this instruction is a branch_type or not
      branch_instruction = self.__is_branch_inst(ins.groups)
      
      # return a list with the immediate values
      imediate_operator = self.__get_immediate_operators(ins.operands)

      # increases the value of num_of_memory_access when the instruction has memory operators
      self.__compute_memory_access(ins.operands)


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
