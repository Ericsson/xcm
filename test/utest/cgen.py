import time
import os

def macro_to_file_name(filename):
    return filename.upper().replace(".", "_")

class CFile:
    def __init__(self, path):
        self.filename = os.path.basename(path)
        self.file = open(path, "w")
    def include(self, filename):
        self.write("#include \"%s\"\n\n" % filename)
    def includes(self, filenames):
        for f in filenames:
            self.include(f)
    def baseinclude(self, path):
        self.include(os.path.basename(path))
    def baseincludes(self, paths):
        for p in paths:
            self.include(os.path.basename(p))
    def comment(self, str):
        if str.find("\n") == -1:
            self.write("/* %s &*/\n" % str)
        else:
            self.write("/**\n")
            for l in str.split("\n"):
                self.write(" * %s\n" % l)
            self.write(" */\n\n")
    def autogen_notice(self):
        self.comment("""%s

Automatically generated at %s. Do not edit!
""" % (self.filename, time.ctime()))
    def write(self, data):
        self.file.write(data)
    def close(self):
        self.file.close()
        
class ImplFile (CFile):
    def __init__(self, path):
        CFile.__init__(self, path)
    def header(self):
        self.autogen_notice()
    def footer(self):
        pass

class HeaderFile (CFile):
    def __init__(self, path):
        CFile.__init__(self, path)
    def start_guard_macro(self):
        self.write("#ifndef %s\n" % macro_to_file_name(self.filename))
        self.write("#define %s\n\n" % macro_to_file_name(self.filename))
    def end_guard_macro(self):
        self.write("#endif /* %s */\n" % macro_to_file_name(self.filename))
    def header(self):
        self.start_guard_macro()
        self.autogen_notice()
    def footer(self):
        self.end_guard_macro()
