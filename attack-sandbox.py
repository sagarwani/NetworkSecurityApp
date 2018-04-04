import ParallelTSP_mobile
maxPaths,  numToPath, shortestPath = ParallelTSP_mobile.maxPaths, ParallelTSP_mobile.numToPath, ParallelTSP_mobile.computeShortestPath
import sys
import os
sys.path.append("../../../Playground3-MobileCode/src")
sys.path.append("../../../BitPoints-Bank-Playground3-")
from MobileCodeService.Packets import MobileCodePacket, MobileCodeFailure
from MobileCodeService.Auth import IMobileCodeServerAuth, NullClientAuth, SimplePayingClientAuth
from MobileCodeService.Wallet import NullClientWallet, PayingClientWallet
from MobileCodeService.Client import MobileCodeClient, MobileCodeServerTracker
from MobileCodeService.Packets import GeneralFailure
from ui.CLIShell import CLIShell, AdvancedStdio
from playground.common import Timer, Minutes, Seconds
from cryptography.hazmat.backends import default_backend
import playground
from asyncio import get_event_loop, Protocol, Future
import random, logging, sys, os, getpass, math, datetime, time, shutil, subprocess, asyncio
import _pickle as cPickle
from playground.asyncio_lib.SimpleCondition import SimpleCondition

logger = logging.getLogger("playground.org,"+__name__)
backend = default_backend()

def getCertFromBytes(pem_data):
    return x509.load_pem_x509_certificate(pem_data, backend)
	
#with open("attack.py") as f:
#    mobileCode = f.read()

class team4():
    def __init__(self, auth, wallet):
        self.auth = auth
        self.wallet=wallet
        self.connector = "default"
        self.myip='20174.1.369.40'
        self.list = [4,12]
        self.address = {}
        self.address['team1']='20174.1.1994.2'
        self.address['team2']='20174.1.11.1'
        self.address['team3']='20174.1.12321.666'
        self.address['team4']='20174.1.62033.27182'
        self.address['team5']='20174.1.9596.5'
        self.address['team6']='20174.1.12646.1'
        self.address['team7']='20174.1.6666.1'
        self.address['team8']='20174.1.369.40'
        self.address['team9']='20174.1.1314.2'
        self.address['team10'] ='20174.1.666.1'
        self.address['team11'] ='20174.1.2333.2333'
        self.address['team12'] ='20174.1.636.200'
        self.address['team13'] ='20174.1.5810.1'
        #self.address['team13'] = '20174.1.1337.1'
        #self.address['team14'] = '20174.1.1337.2'
        #self.address['team15'] = '20174.1.1337.3'
        #self.address['team16'] = '20174.1.1337.4'
        #self.address['team17'] = '20174.1.1337.5'
        #self.address['team18'] = '20174.1.1337.6'
        self.sir = {}
        self.sir['1'] = '20174.1.1337.1'
        self.sir['2'] = '20174.1.1337.2'
        self.sir['3'] = '20174.1.1337.3'
        self.sir['4'] = '20174.1.1337.4'
        self.sir['5'] = '20174.1.1337.5'
        self.sir['6'] = '20174.1.1337.6'
        self.port = 1
        self.mobileCode=""
		
        with open("customMobileCode.py") as f:
            self.mobileCode = f.read()
        #for x in range(1,13):
        #for x in range(3,6):
        for x in self.list:
            self.addrx = self.address['team'+str(x)]
            #self.addrx=self.sir[str(x)]
            oneShotClient = MobileCodeClient(self.connector, self.addrx, self.port, self.mobileCode, self.auth,  self.wallet)
            # MobileCodeClient(connector, address, port, mobileCode, auth, wallet)
            result = oneShotClient.run()
            #result.add_done_callback(closure(codeId, oneShotClient))
	
def main():
    from OnlineBank import BankClientProtocol, BANK_FIXED_PLAYGROUND_ADDR, BANK_FIXED_PLAYGROUND_PORT
    from CipherUtil import loadCertFromFile
    #logctx = LoggingContext()
    #logctx.nodeId = "parallelTSP_"+myAddr.toString()
    # set this up as a configuration option
    #logctx.doPacketTracing = True
    #playground.playgroundlog.startLogging(logctx)

    # Having placeHolders for asyncio

    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    ptspArgs = {}
    
    from playground.common.logging import EnablePresetLogging, PRESET_VERBOSE, PRESET_DEBUG
    EnablePresetLogging(PRESET_DEBUG)
        
    args= sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
                k,v = arg.split("=")
                ptspArgs[k]=v
        else:
                ptspArgs[i] = arg
                i+=1
    stack = ptspArgs.get("-stack","default")
    bankAddress = ptspArgs.get("-bankaddr", BANK_FIXED_PLAYGROUND_ADDR)
    bankPort = ptspArgs.get("-bankport", BANK_FIXED_PLAYGROUND_PORT)
            
    tracker = MobileCodeServerTracker()
    tracker.startScan()

    bankcert = loadCertFromFile(ptspArgs[0])
    payeraccount = ptspArgs[2]
    username = args[1]
    pw = getpass.getpass("Enter bank password for {}: ".format(username))

    bankstackfactory = lambda: BankClientProtocol(bankcert, username, pw)
    wallet = PayingClientWallet(stack, bankstackfactory, username, pw, payeraccount,
                                bankAddress, bankPort)

    clientAuth = SimplePayingClientAuth()
    team4(clientAuth, wallet)      

    # loop.set_debug(enabled=True)
    #loop.call_soon(initShell)

    
    # TODO - Will switchAddr be changed to "localhost" ?
    # stack can be "default" or user provided stack from ~/.playgroun/connector
    
    
    #parallelMaster = MobileCodeClient(stack, switchAddr, port, samplecode, NullClientAuth(), NullClientWallet())
    #coro = playground.getConnector(stack).create_playground_connection(lambda: TwistedStdioReplacement.StandardIO(ParallelTSPCLI(configOptions, parallelMaster)),switchAddr, port)
    #transport, protocol = loop.run_until_complete(coro)
    loop.run_forever()
    tracker.stopScan()
    loop.close()

    
if __name__ == "__main__":
    main()
