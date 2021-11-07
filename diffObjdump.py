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
    for d1_func in d1_func_names:
      if(d1_func in d2_func_names):
        pass
      else:
        pass
      # called functions and the respectice count, memory access count, branches count
      # check if {dump2} also have such function name:
        # if so: compute stats and compare one by one with the {dump1} stats
        # else: print a report informing that {dump2} does not have such function, and print {dump1} stats

    # for the remaining function names in the set of {dump2}, report that {dump1} does not have such function
    # and print this function information
    pass