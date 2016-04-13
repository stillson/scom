import code
import SocketServer
import sys
import time

class SocketConsole(code.InteractiveConsole):
    def __init__(self, server, handler):
        self.server = server
        self.handler = handler
        self.locals = self.server.my_hidden
        self.filename = '<Socket Console>'
        code.InteractiveInterpreter.__init__(self, self.locals)
        self.resetbuffer()

    def write(self, data):
        self.handler.wfile.write(data)

    def raw_input(self, prompt='>>> '):
        if prompt:
            time.sleep(.1)
            self.write(prompt)
        return self.handler.rfile.readline()

    def runcode(self, code):
        saved_stdout = sys.stdout
        sys.stdout = self.handler.wfile
        try:
            exec code in  self.locals
        except SystemExit:
            raise
        except:
            self.showtraceback()
        finally:
            sys.stdout = saved_stdout


class ConsoleHandlerClass(SocketServer.StreamRequestHandler):
    def handle(self):
        print 'ConsoleHandlerClass -> handle'
        console = SocketConsole(self.server, self)
        console.interact()

TCP = False
if TCP:
    ServerClass = SocketServer.ThreadingTCPServer
    address = ('127.0.0.1', 7777)
else:
    ServerClass = SocketServer.ThreadingUnixStreamServer
    address = '/tmp/bdserv'
    try:
        import os
        os.remove(address)
    except:
        pass

def start(locals):
    ServerClass.allow_reuse_address = True
    ServerClass.my_hidden = locals
    srv = ServerClass(address, ConsoleHandlerClass)
    print "serving on backdoor"
    srv.serve_forever()

if __name__ == '__main__':
    start(locals())
