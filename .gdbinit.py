import gdb.printing

def kind_to_str(kind):
  kind = int(kind)
  switch = {
    0: "UECALL",
    1: "RETURN",
    2: "SECALL",
    3: "TIMESTAMP",
    4: "EXCEPTION",
    5: "PCHI"
  }
  return switch.get(kind, "invalid")

def kind_to_field(kind):
  kind = int(kind)
  switch = {
    0: "ecall",
    1: "ret",
    2: "ecall",
    3: "timestamp",
    4: "exception",
    5: "pchi"
  }
  return switch.get(kind, "val")

class owl_trace_field_printer:
  """Print an owl_trace union field."""

  def __init__(self, val):
      self.val = val

  def to_string(self):
    return None

  def children(self):
    kind = self.val["kind"]
    for field in self.val.type.fields():
      key = field.name
      val = self.val[key]
      if key == "kind":
        yield key, "<" + kind_to_str(val) + ">"
      elif key == "pc":
          yield key, hex(val)
      elif key == "priv":
          yield key, hex(val)
      else: yield key, val

class owl_trace_printer:
  """Print an owl_trace union."""

  def __init__(self, val):
      self.val = val

  def to_string(self):
    return None

  def children(self):
    kind = self.val["kind"]
    yield kind_to_field(kind), self.val[kind_to_field(kind)]

class callstack_printer:
  """Print a callstack struct."""

  def __init__(self, val):
      self.val = val

  def to_string(self):
    return None

  def children(self):
    yield "from_frame", self.val["from_frame"]
    yield "to_frame", self.val["to_frame"]
    for field in self.val.type.fields():
      key = field.name
      val = self.val[key]
      if key == "from_frame" or key == "to_frame": continue
      elif key == "frames":
        if not val: yield key, "NULL"
        else:
          yield key + "[0]", (val+0).dereference()
          yield key + "[1]", (val+1).dereference()
          yield key + "[2]", (val+2).dereference()
      else:
        yield key, val


def build_pretty_printer():
  pp = gdb.printing.RegexpCollectionPrettyPrinter("owl")
  pp.add_printer('owl_trace', '^owl_trace$', owl_trace_printer)
  pp.add_printer('owl_.*_trace', '^owl_.*_trace$', owl_trace_field_printer)
  pp.add_printer('callstack', '^callstack$', callstack_printer)
  return pp

gdb.printing.register_pretty_printer(
  gdb.current_objfile(),
  build_pretty_printer())
