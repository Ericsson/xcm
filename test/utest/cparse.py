import re

c_fun_re = re.compile(r"\s*((?:const\s*)?(?:struct\s*)?(?:unsigned\s*)?(?:signed\s*)?[\w_]+\s*\*?\s*)\s*(\w+)\s*\(\s*([\*\w\n \t,]*)\s*\)\s*;", re.MULTILINE)

BLK_COMMENT_START = "/*"
BLK_COMMENT_END = "*/"
LINE_COMMENT_START = "//"
LINE_COMMENT_END = "\n"

# there are a number of limitations with this approach - for example, we
# do not handle comments characters within string properly

def _remove_comments(withcomments, comment_start, comment_end, eof_is_end):
    nocomments = ""
    while True:
        blk_start = withcomments.find(comment_start)
        if blk_start != -1:
            blk_end = withcomments.find(comment_end, blk_start)
            if blk_end == -1 and eof_is_end:
                blk_end = len(withcomments)
            if blk_end != -1:
                nocomments += withcomments[:blk_start]
                withcomments = withcomments[blk_end+len(comment_end):]
            else:
                return nocomments+withcomments
        else:
            return nocomments+withcomments

def remove_comments(withcomments):
    nocomment = _remove_comments(withcomments, BLK_COMMENT_START,
                                 BLK_COMMENT_END, 0)
    nocomment = _remove_comments(nocomment, LINE_COMMENT_START,
                                 LINE_COMMENT_END, 1)
    return nocomment

class CType:
    def __init__(self, type):
        # canonical form
        self.type = re.sub("\s+", " ", re.sub("\s+\\*", "*", type.strip()))
        if self.type == "short int":
            self.type == "short"
    def is_pointer(self):
        return self.type.find("*") != -1
    def is_const(self):
        return self.type.find("const") != -1
    def dereference(self):
        assert self.is_pointer()
        return CType(self.type[0:self.type.rfind("*")])
    def strip_const(self):
        return CType(self.type.replace("const", ""))
    def pointer_to(self):
        return CType(self.type+"*")
    def const_unqualify(self):
        # refer to 6.2.5 of the ISO/IEC 9899:1999(E) for an explaination what
        # a qualified type is
        c = self.type.rfind("const")
        p = self.type.find("*")
        if c == -1:
            return CType(self.type)
        elif p == -1:
            return CType(self.type.replace("const", ""))
        else:
            if c > p:
                return CType(self.type[:c]+self.type[c+len("const"):])
            else:
                return CType(self.type)
    def is_const_qualified(self):
        return self.type != self.const_unqualify().type
    def is_void(self):
        return self.type == "void"
    def is_bool(self):
        return self.type == "bool"
    def is_char(self):
        return self.type == "char"
    def is_short(self):
        return self.type == "short"
    def is_unsigned_short(self):
        return self.type == "unsigned short"
    def is_float(self):
        return self.type == "float"
    def is_c_str(self):
        return self.type == "char*" or self.type == "const char*"
    def is_struct(self):
        # this is only true for non-typedefs
        return self.type.rfind("struct ") != -1
    def va_arg_type(self):
        # doesn't work for typedefs...
        if self.is_bool() or self.is_char() or self.is_short() or \
                self.is_unsigned_short():
            return CType("int")
        elif self.is_float():
            return CType("double")
        else:
            return CType(self.type)
    def __str__(self):
        return self.type

class CFunctionArgument:
    def __init__(self, type, name):
        self.type = type
        self.name = name
    def may_be_out_parameter(self):
        return self.type.is_pointer() and \
            not self.type.is_const() and \
            not self.type.dereference().is_void()

class CFunction:
    def __init__(self, return_type, name, arguments):
        self.return_type = return_type
        self.name = name
        self.arguments = arguments
    def arg_list(self):
        l = ""
        if len(self.arguments) > 0:
            p = self.arguments[0]
            l += "%s %s" % (p.type, p.name)
            for n in self.arguments[1:]:
                l += ", %s %s" % (n.type, n.name)
        return l
    def arg_names(self):
        return [arg.name for arg in self.arguments]
    def n_args(self):
        return len(self.arguments)
    def __str__(self):
        return "%s%s%s(%s)" % (self.return_type, self.name, self.arguments)

#arg_re = re.compile(r"^([\w\s]+?)(\**\s*)(\s*[\w]+)$")
# changed to following to support "char * const foo"
# *? means non-greedy. This won't separate * and insert a space before
# but it works with the following cases:
arg_re = re.compile(r"^(.*?)([\w]+)$")

def parse_args(args_s):
    l = args_s.replace("\n", " ").replace("\t", " ").split(",")
    arguments = []
    for p in l:
        p = p.strip()
        if p != '':
            m = arg_re.match(p)
            if m:
                type_parts = filter(None, m.groups())
                type_parts = [e.strip() for e in type_parts]
                atype = " ".join(type_parts[0:-1]).strip()
                aname = type_parts[-1]
#                print("atype '%s' aname '%s'" % (atype, aname))
                arguments.append(CFunctionArgument(CType(atype), aname))
            else:
                raise IOError("Invalid function parameters \"%s\"" % p)
    return arguments

def parse_fun(s):
    m = c_fun_re.search(s)
    if m:
        left = s[m.span()[1]:]
        return (left, CFunction(CType(m.groups()[0].strip()), m.groups()[1],
                                parse_args(m.groups()[2])))
    else:
	return ("", None)

def parse_functions(proxy_targets):
    funs = []
    while len(proxy_targets) > 0:
        (proxy_targets, fun) = parse_fun(proxy_targets)
        if fun:
            funs.append(fun)
    return funs

def parse_functions_from_files(files):
    data = ""
    for f in files:
        data += open(f).read()
    funs = parse_functions(data)
    return funs
