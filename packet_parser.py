import binascii
import string
#TODO: try and except for every function
#TODO: if raw data is printable, convert it to ascii

class parser():
    def __init__(self, packet):
        self.packet = binascii.unhexlify(packet)
        self.original_packet = packet
        self.general_mappings = {
            ord(b'!'): lambda: self.return_msg(b"Extended-Mode enabled"),
            ord(b'?'): lambda: self.return_msg(b"Target halted"),
            ord(b'A'): lambda: self.initialize_argv(),
            ord(b'B'): lambda: self.set_breakpoint(),
            ord(b'b')+ord(b'c'): lambda: self.return_msg(b"Backward continue"),
            ord(b'b')+ord(b's'): lambda: self.return_msg(b"Backward single step"),
            ord(b'D'): lambda: self.detuch_debug(),
            ord(b'F'): lambda: self.f_reply(),
            ord(b'g'): lambda: self.return_msg(b"Reading general registers"),
            ord(b'G'): lambda: self.return_msg(b"Writing to general registers"),
            ord(b'H'): lambda: self.set_thread_op(),
            ord(b'i'): lambda: self.step_cycle(),
            ord(b'I'): lambda: self.return_msg(b"Signal, then cycle step"),
            ord(b'k'): lambda: self.return_msg(b"Kill request"),
            ord(b'm'): lambda: self.read_memory(),
            ord(b'M'): lambda: self.write_memory(),
            ord(b'p'): lambda: self.read_register(),
            ord(b'P'): lambda: self.write_register(),
            ord(b'R'): lambda: self.return_msg(b"Restart the program being debugged"),
            ord(b's'): lambda: self.single_step(),
            ord(b'S'): lambda: self.step_with_single(),
            ord(b't'): lambda: self.search_backwards(),
            ord(b'T'): lambda: self.find_thread(),
            ord(b'X'): lambda: self.write_data(),
            ord(b'E'): lambda: self.return_msg(b"[*] Response: Error number " + self.packet)
        }
        self.v_mappings={
            b'vAttach': lambda: self.return_msg(b"Attach to pid " + self.packet.split(b';')[1]),
            b'vCont': lambda: self.resume_inferior(),
            b'vCont?': lambda: self.return_msg(b"Reuqest a list of actions supported by the vCont packet"),
            b'vCtrlC': lambda: self.return_msg(b"Interrupt remote target (Ctrl-C)"),
            b'vFile': lambda: self.file_operation(),
            b'vFlashErase': lambda: self.flash_erase(),
            b'vFlashWrite': lambda: self.flash_write(),
            b'vFlashDone': lambda: self.return_msg(b"Flash programming operation is done"),
            b'vKill': lambda: self.return_msg(b"Kill process " + self.packet[1:]),
            b'vMustReplyEmpty': lambda: self.return_msg(b"Check how gdbserver handles unknown packets (vMustReplyEmpty)"),
            b'vRun': lambda: self.run_program(),
            b'vStopped': lambda: self.return_msg(b"vStop: Asynchronous stop event in non-stop mode")
        }
        self.errorcodes = {
            1: "Operation not permitted",
            2: "No such file or directory",
            9: "Bad file number",
            10: "No child processes",
            13: "Permission denied",
            14: "Bad address",
            16: "Device or resource busy",
            17: "File exists",
            19: "No such device",
            20: "Not a directory",
            21: "Is a directory",
            22: "Invalid argument",
            23: "File table overflow",
            24: "Too many open files",
            27: "File too large",
            28: "No space left on device",
            29: "Illegal seek",
            30: "Read-only file system",
            91: "Protocol wrong type for socket",
            9999: "Unknown error"
        }
        self.q_mappings={
            b"QAgent" : lambda: self.agent_op(),
            b'QAllow' : lambda: self.gdb_operations(),
            b'qC' : lambda: self.return_msg(b"Return the current thread id"),
            b'qCRC': lambda: self.calc_crc(),
            b'QDisableRandomization': lambda: self.set_command(b"Target will use address randomization (ASLR)",b"Target will not use address randomization (ASLR)"),
            b'QStartupWithShell': lambda: self.set_shell(),
            b'QEnvironmentHexEncoded': lambda: self.return_msg(b"Environmental variable '" + self.packet + b"' will be passsed to the inferior process"),
            b'QEnvironmentUnset': lambda: self.return_msg(b"Environmental variable '" + self.packet + b"' will be unset in the inferior process"),
            b'QEnvironmentReset': lambda: self.return_msg(b"Reset the state of environment variables"),
            b'QSetWorkingDir': lambda: self.return_msg(b"Current directory is set to '" + self.packet + b"'"),
            b'qfThreadInfo': lambda: self.return_msg(b"Obtain a list of all active thread IDs"),
            b'qsThreadInfo': lambda: self.return_msg(b"Obtain a list of all active thread IDs"),
            b'qGetTLSAddr': lambda: self.fetch_addr(),
            b'qGetTIBAddr': lambda: self.return_msg(b"Fetch address of windows os specific thread with id: " + self.packet),
            #'qL' is depricated
            b'qOffsets': lambda: self.return_msg(b"Get section offsets that the target used when relocating the downloaded image"),
            #'qP' is depricated
            b'QNonStop': lambda: self.set_command(b"Enter non stop mode", b"Enter all-stop mode"),
            b'QCatchSyscalls': lambda: self.enable_syscalls(),
            b'QProgramSignals': lambda: self.return_msg(b"The following signals *may* be delievered to the inferior process: " + self.packet),
            b'QPassSignals': lambda: self.return_msg(b"The following signals will be delivered to the inferior process: " + self.packet),
            b'QThreadEvents': lambda: self.set_command(b"Enable reporting of thread create and exit events",b"Disable reporting of thread create and exit events"),
            b'qRcmd': lambda: self.return_msg(b"Command " + self.packet + b" is passed for execution"),
            b'qSearch': lambda: self.search_bytes(),
            b'QStartNoAckMode': lambda: self.return_msg(b"Request to disable normal '+'/'-' protocol acknowledgments"),
            b'qSupported': lambda: self.query_feature(),
            b'qSymbol': lambda: self.symbol_lookup(),
            b'qXfer': lambda: self.io_object(),
            b'qAttached': lambda: self.return_msg(b"Return an indication of whether the remote server atthached to process with pid " + self.packet),
            b'Qbtrace': lambda: self.qbtrace(),
            b'Qbtrace-conf': lambda: self.qbtrace_conf(),
            ## Tracepoint Packets ##
            b'QTDP': lambda: self.create_tracepoint(),
            b'QTDPsrc': lambda: self.source_string(),
            b'QTDV': lambda: self.new_tace_var(),
            b'QTFrame': lambda: self.select_tracepoint(),
            b'qTMinFTPILen': lambda: self.return_msg(b"Request the minimum length of instructions of which a fast tracepoint may be placed"),
            b'QTStart': lambda: self.return_msg(b"Begin the tracepoint experiment. Begin collecting data from tracepoint hits in the trace frame buffer"),
            b'QTStop': lambda: self.return_msg(b"End the tracepoint experiment. Stop collecting trace frames."),
            b'QTEnable': lambda: self.set_qt(True),
            b'QTDisable': lambda: self.set_qt(False),
            b'QTinit': lambda:self.return_msg(b"Clear the table of tracepoints, and empty the trace frame buffer"),
            b'QTro': lambda:self.est_transperant(),
            b'QTDisconnected': lambda: self.return_msg(b"When GDB disconnects, tracing status will be: " + self.packet),
            b'qTStatus': lambda: self.return_msg(b"Ask the stub if there is a trace experiment running right now"),
            b'qTV': lambda:self.return_msg(b"Ask the stub for the value of the trace state variable number " + self.packet),
            b'qTfP': lambda:self.return_msg(b"Request data about tracepoints that are being used by the target"),
            b'qTsP': lambda: self.return_msg(b"Request data about tracepoints that are being used by the target"),
            b'qTfV': lambda:self.return_msg(b"Request data about trace state variables that are on the target"),
            b'qTsV': lambda: self.return_msg(b"Request data about trace state variables that are on the target"),
            b'qTfSTM': lambda:self.return_msg(b"Request data about static tracepoint markers that exist in the target program"),
            b'qTsSTM': lambda: self.return_msg(
                b"Request data about static tracepoint markers that exist in the target program"),
            b'qTSTMat': lambda:self.return_msg(b"Request data about static tracepoint markers in the target program at address " + self.packet),
            b'QTSave': lambda:self.return_msg(b"Directs the target to save trace data to the file name " + self.packet + b" in the target's filesystem"),
            b'qTBuffer': lambda: self.return_buf(),
            b'QTBuffer': lambda: self.qt_buffer(),
            b'QTNotes': lambda: self.qtnotes()
        }
        self.z_mappings={
            b'Z': lambda: self.set_bp(True, 't'),
            b'z': lambda: self.set_bp(False, 't'),
            b'Z0': lambda: self.set_bp(True, 's'),
            b'z0': lambda: self.set_bp(False, 's'),
            b'Z1': lambda: self.set_bp(True, 'h'),
            b'z1': lambda: self.set_bp(False, 'h'),
            b'Z2': lambda: self.set_bp(True, 'w'),
            b'z2': lambda: self.set_bp(False, 'w'),
            b'Z3': lambda: self.set_bp(True, 'wr'),
            b'z3': lambda: self.set_bp(False, 'wr'),
            b'Z4': lambda: self.set_bp(True, 'aw'),
            b'z4': lambda: self.set_bp(False, 'aw')
        }

    def is_printable(self,str):
        return all(c in string.printable for c in str)

    def set_bp(self,op,tp):
        packet = self.packet.split(b',')
        if len(packet) == 3:
            type, addr, kind = packet
        else:
            addr, kind = packet
        if op and tp=='t':
            return b"Insert a " + type + b" breakpoint or watchpoint at address " + addr + b" of kind " + kind
        elif op and tp == 's':
            return b"Insert a software breakpoint at address " + addr + b" of type " + kind
        elif op and tp == 'h':
            return b"Insert a hardware breakpoint at address " + addr + b" of type " + kind
        elif op and tp == 'w':
            return b"Insert a write watchpoint " + addr + b" of type " + kind
        elif op and tp == 'aw':
            return b"Insert an access watchpoint " + addr + b" of type " + kind
        elif not op and tp == 'aw':
            return b"Remove an access watchpoint address " + addr + b" of type " + kind
        elif op and tp == 'wr':
            return b"Insert a read watchpoint " + addr + b" of type " + kind
        elif not op and tp == 'wr':
            return b"Remove a read watchpoint address " + addr + b" of type " + kind
        elif not op and tp == 'w':
            return b"Remove a write watchpoint address " + addr + b" of type " + kind
        elif not op and tp == 'h':
            return b"Remove a hardware breakpoint address " + addr + b" of type " + kind
        elif not op and tp == 's':
            return b"Remove a software breakpoint at address " + addr + b" of type " + kind
        else:
            return b"Remove a " + type + b" breakpoint or watchpoint at address " + addr + b" of kind " + kind

    def write_data(self):
        addr_len,data = self.packet.split(b':')
        addr,len=addr_len.split(b',')
        return b"Write data to address " + addr + b" with len of " + len + b". Data: \n " + self.expand_stream(data)

    def qtnotes(self):
        tnotes = self.packet.split(b';')
        rtn_msg=b"Add optional textual notes to the trace run. The following settings: "
        for note in tnotes:
            rtn_msg += note + b", "
        return  rtn_msg[:-2]

    def return_buf(self):
        offset,len=self.packet.split(b',')
        return b"Return " + len + b" bytes of the current contents of trace buffer start at " + offset

    def qt_buffer(self):
        param1,param2 = self.packet.replace(b',',b':').split(b':')
        if param1 == b'circular':
            if param2 == b'1':
                return b"Use a circular trace buffer"
            else:
                return b"Use a linear trace buffer"
        else:
            if param2 != b'-1':
                return b"Trace a buffer of size " + param2
            else:
                return b"Trace a buffer"

    def est_transperant(self):
        ranges = self.packet.split(b':')
        rtn_msg=b"Establish the following ranges as transparent: "
        for range in ranges:
            rtn_msg += range.replace(b',',b'-') + b", "
        return rtn_msg[:-2]

    def set_qt(self, op):
        n,addr = self.packet.split(b':')
        if op:
            return b"Enable tracepoint " + n + b" at address " + addr
        else:
            return b"Disable tracepoint " + n + b" at address " + addr

    def select_tracepoint(self):
        packet = self.packet.split(b':')
        rtn_msg = b""
        if len(packet) == 1:
            return b"Select the " + packet + b"'th tracepoint from the buffer"
        elif packet[0] == b"pc":
            return b"Select the first tracepoint frame after the currently selected frame whose PC address is " + packet[1]
        elif packet[0] == b"tdp":
            return b"Select the first tracepoint frame after the currently selected frame that is a hit of tracepoint " + packet[1]
        elif packet[0] == b"range":
            return b"Select the first tracepoint frame whose PC is between " + packet[1] + b" and "+ packet[2] + b" addresses"
        else:
            return b"Select the first tracepoint frame whose PC is *outside* " + packet[1] + b" and "+ packet[2] + b" addresses"

    def new_tace_var(self):
        n,value,builtin,name = self.packet.split(b':')
        return b"Create a new trace state variable '"+name+b"' (number " + n + b" ) with initial value="+value+b" .Builtin status: " + builtin

    def source_string(self):
        n,addr,type,start,slen,bytes = self.packet.split(b':')
        return b"Tracepoint #"+n+b" at address " + addr + b" with type " + type + b" . Source string: " + bytes + b" start with offset " + start

    def create_tracepoint(self):
        packet = self.packet.split(b':')
        if packet[0][0] == ord('-'):
            rtn_msg= b"Follow up for actions [number " + packet[0][1:] + b"] at address " + packet[1] + b" with the following actions: " + packet[2][-1]
            if packet[2][-1]==ord('-'):
                rtn_msg+=b"\n QTDP packet will follow to specify this tracepoint's actions"
            return  rtn_msg
        else:
            status = b"Enabled" if packet[2] == b'E' else b"Disabled"
            rtn_msg = b"Create a new tracepoint numbered " + packet[0] + b" at address " + packet[1] + b" with status " + status\
            + b" and step count = " + packet[3] + b"."
            if b'F' in self.packet:
                rtn_msg += b" Fast tracepoint is enabled with flen of " + packet[5][1:] + b"."
            if b'X' in self.packet:
                _,bytes = packet[6].split(b',')
                if chr(bytes[-1]) == '-':
                    rtn_msg += b" Tracepoint condition: " + bytes[:-1] + b"\n QTDP packet will follow to specify this tracepoint's actions"
                else:
                    rtn_msg += b" Tracepoint condition: " + bytes[:-1]
            return rtn_msg

    def qbtrace_conf(self):
        op,_,size = self.packet.replace(b'=',b':').split(b':')
        return b"Set the requested ring buffer size in " + op + b" format with size of " + size

    def qbtrace(self):
        if b'bts' == self.packet:
            return b"Enable branch tracing for the current thread using BTS"
        elif b'pt' == self.packet:
            return b"Enable branch tracing for the current thread using IPT"
        else:
            return b"Disable branch tracing for the current thread"

    def enable_syscalls(self):
        if b';' in self.packet:
            syscalls = self.packet.split(b';')
            return b"Catch the following syscalls: " + b','.join(syscalls[1:])
        elif self.packet == ord(b'1'):
            return b"Catch all syscalls"
        else:
            return b"Disable syscall catching"

    def io_object(self):
        packet = self.packet.split(b':')
        if len(packet) == 2:
            object, operation = self.packet.split(b':')
            return b"Operation " + operation + b" may be added in the future for object " + object
        object,op,annex,offset,length = self.packet.replace(b':',b';').replace(b',',b';').split(b';')
        if op == b'write':
            return b"Write uninterpreted bytes from object " + object + b" with length of " + length + b" starting at " + offset\
                    + b". Additional params info: " + annex
        else:
            return b"Read uninterpreted bytes from object " + object + b" with length of " + length + b" starting at " + offset \
                   + b". Additional params info: " + annex

    def symbol_lookup(self):
        try:
            if len(self.packet) == 1:
                return b"GDB is prepared to serve symbol lookup requests"
            else:
                sym_val,sym_name = self.packet.split(b':')
                try:
                    if self.is_printable(binascii.unhexlify(sym_name).decode()):
                        sym_name = binascii.unhexlify(sym_name)
                except:
                    pass
                return b"Set the value of " + sym_name + b" to " + sym_val
        except:
            return b"Unrecognized/Unsupported command for (qsymbol lookup): " + self.expand_stream(self.packet)
    def query_feature(self):
        features = self.packet.split(b';')
        msg=b"Features supported by GDB: "
        for feature in features:
            msg+=feature + b", "
        return msg[:-2]

    def search_bytes(self):
        mem,addr,len,searchp = self.packet.replace(b':',b';').split(b';')
        return b"Search for pattern " + searchp + b" at address " + addr + b" with length of " + len

    def fetch_addr(self):
        thread_id,offset,lm = self.packet.split(',')
        return b"Fetch address associated with thread id: " + thread_id + b" with offset " +offset + b" with lm: " + lm

    def set_shell(self):
        if self.packet == b'1':
            return b"GDB will use shell to start the inferior process"
        else:
            return b"GDB will use not use a shell to start the inferior process"

    def set_command(self, onm, offm):
        if self.packet == b'1':
            return onm
        else:
            return offm

    def calc_crc(self):
        addr,len = self.packet.split(b',')
        return b"Compute CRC checksum at address " + addr + b" with len of " + len

    def gdb_operations(self):
        op,val = self.packet.split(b':')
        if val == b'1':
            return b"GDB expects to request the following operation: " + op
        else:
            return b"GDB will not request the following operation: " + op

    def agent_op(self):
        packet = self.packet.split(b':')
        if packet[1] == b'1':
            return b"Turn agent on"
        else:
            return b"Turn agent off"

    def run_program(self):
        prog_name = self.packet[1:].split(b';')
        msg = b"Run the program \"" + prog_name[0] + b"\""
        if len(prog_name) > 1:
            msg+= b" with args: " + prog_name[1]
        return msg

    def flash_write(self):
        addr,content = self.packet[1:].split(b':')
        return b"Write to address " + addr + b" content: " + content

    def flash_erase(self):
        addr,length = self.packet[1:].split(b',')
        return b"Erase " + length + b" bytes of flash starting at " + addr

    def file_operation(self):
        operation,params = self.packet[1:].split(b':')
        params = params.split(b',')
        if operation == b'open':
            for i in range(len(params)):
                try:
                    _p = binascii.unhexlify(params[i]).decode()
                    if self.is_printable(_p):
                        params[i] = _p.encode()
                except:
                    pass
        return b"File operation: " + operation + b" with params: " + b','.join(params)

    def resume_inferior(self):
        if b':' in self.packet:
            packet,thread_id = packet = self.packet.split(b':')
            packet = packet[0][1:]
        elif b';' in self.packet:
            packet = self.packet.split(b';')[1]
        else:
            return b"Continue"
        action = {
            ord(b'c'): b"Continue",
            ord(b'C'): b"Continue with signal " + packet[1:],
            ord(b's'): b"Step",
            ord(b'S'): b"Step with signal " + packet[1:],
            ord(b't'): b"Stop",
            ord(b'r'): False
        }
        if not action[packet[0]]:
            r1,r2 = packet.split(b',')
            msg = b"Step once and keep stepping as long as between addresses " + r1 + b", " + r2
        else:
            msg = action[packet[0]]
        if 'thread_id' in locals():
            return msg + b" with thread id " + thread_id
        else:
            return msg

    def find_thread(self):
        return b"Find if thread " + self.packet + b" is alive"

    def search_backwards(self):
        addr,patmask = self.packet.split(b':')
        pp,mm = patmask.split(b',')
        return b"Searching backwards at address " + addr + b" with pattern " + pp + b" and with mask " + mm

    def step_with_single(self):
        s = b"Stepping with signal " + self.packet.split(b';')[0]
        addr = self.packet.split(b';')
        if len(addr) == 2:
            s += b" at address " + addr[1]
        return s

    def single_step(self):
        s = b"Single step"
        if len(self.packet) > 0:
            s+= b" resuming at address " + self.packet
        return s

    def write_register(self):
        reg_num,data = self.packet.split(b'=')
        return b"Write " + data + b" into register number " + reg_num

    def read_register(self):
        return b"Read the value of register " + self.packet

    def read_memory(self):
        packet = self.packet.split(b',')
        return b"Read memory at address " + packet[0] + b" with a length of " + packet[1]

    def write_memory(self):
        addr,length = self.packet.split(b',')
        length,data = length.split(b':')
        return b"Write memory at address " + addr + b"with a length of " + length + b" with data: " + data

    def step_cycle(self):
        info = b"Step the remote target"
        if len(self.packet) == 0:
            info += b" with a clock cycle"
            return info
        a = self.packet.split(b',')
        info += b" at address: " + a[0]
        if len(a) == 2:
            info += b" with "+ a[1] + b" clock cycles"
        return info

    def set_thread_op(self):
        op = self.packet[:1]
        thread_id = self.packet[1:]
        return b"Thread operation: " + op + b" Thread id: " + thread_id

    def f_reply(self):
        packet = self.packet.split(b',')
        if(len(packet) > 1 and packet[0] == b'-1'):
            error_code = int(packet[1])
            return b"File Error: "+ self.errorcodes[error_code].encode()
        elif len(packet[0].split(b';')) == 1:
            return b"return value = " + packet[0]
        else:
            packet = self.packet[1:].split(b';')
            return_val = packet[0]
            packet = b','.join(packet[1:])
            attachment = self.expand_stream(packet)
            return b"return value = " +  bytes(return_val) + b" raw data: " + binascii.hexlify(attachment.replace(b'}',b'')) #TODO: remove the hexlify?

    def expand_stream(self,datastream):
        expanded=b""
        datastream = datastream.replace(b'\r',b'').replace(b'\n',b'')
        i=0
        while i < len(datastream):
            if(datastream[i] == ord(b'*') and datastream[i-1] != ord(b'}') and i+1 != len(datastream)):
                expanded+=chr(datastream[i-1]).encode()*(datastream[i+1]-29)
                i+=2
            else:
                expanded+=chr(datastream[i]).encode()
                i+=1
        return expanded.replace(b' ',b'') #TODO: maybe not necessary

    def return_msg(self,msg):
        return msg

    def detuch_debug(self):
        packet = self.packet.split(b';')
        if len(packet)==1:
            return b"Detached GDB from the remote system"
        else:
            return b"Detached GDB from process " + packet[1]

    def initialize_argv(self):
    #TODO: convert it to bytes
        packet = self.packet.split(b',')
        new_array = "argv[] = ["
        for i in range(0,len(packet),3):
            new_array+='('+'argument size: '+str(int(packet[i],16)) + ' '
            new_array+=', argnum: '+str(int(packet[i+1],16)) + ' '
            new_array+=', argument: ' + str(packet[i+2]) + '),'
        new_array = new_array[:-2] + ')]'
        return new_array.replace('}','')

    def set_breakpoint(self):
    #TODO: convert to bytes
        packet = self.packet.split(b',')
        return "break at address " + str(packet[0].decode()) + " with mode " + str(packet[1].decode())

    def get_gen_command(self):
        command = 0
        if self.packet[1] == b';':
            command = ord(b'D')
        else:
            for i in range(2):
                byte = self.packet[i]
                command += byte
                if byte != ord(b'b'): # bc, bs are the only commands that have two chars
                    break
                self.packet = self.packet[1:]
        self.packet = self.packet[1:] # now the command is not part of the packet
        return command

    def get_v_command(self):
        vcommand = self.packet.replace(b':',b';').split(b';')[0]
        self.packet = self.packet[len(vcommand):] #remove the command from the packet
        return vcommand

    def get_q_command(self):
        qcommand = b""
        if b':' in self.packet or b',' in self.packet:
            qcommand = self.packet.replace(b',',b':').split(b':')[0]
            self.packet = self.packet[len(qcommand)+1:]
        else:
            qcommand = self.packet
        return qcommand

    def get_parsed_packet(self):
        try:
            if (self.packet[:1] == b'v'):
                return self.v_mappings[self.get_v_command()]
            elif self.packet[0] == ord('Q') or self.packet[0] == ord('q'):
                return self.q_mappings[self.get_q_command()]
            elif self.packet[0] == ord('z') or self.packet[0] == ord('Z'):
                return self.z_mappings[self.get_q_command()]
            else:
                o_command = self.packet
                gen_command = self.get_gen_command()
                if gen_command in self.general_mappings:
                    return self.general_mappings[gen_command]
                else:
                    expanded = self.expand_stream(binascii.unhexlify(self.original_packet))
                    return lambda: self.return_msg(b"[*] Response: " + expanded)
        except:
            return lambda: self.return_msg(b"Unrecognized/Unsupported command: " + self.expand_stream(binascii.unhexlify(self.original_packet)))
