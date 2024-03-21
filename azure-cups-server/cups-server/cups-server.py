from email import header
import json
from typing import Any,Dict,List,Tuple
import base64
import os
import struct
from zlib import crc32
import re
import ast

from flask import request, make_response, jsonify
from flask import abort as fk_abort
from flask import Flask

import db_class as db
import logging
from readconfig import *

app = Flask(__name__)

logging.basicConfig()
logger = logging.getLogger("cups-server")

params = read_params()

### Database Config ### 
db_host = params.get('DB', 'host')
database = params.get('DB', 'database')
user = params.get('DB', 'username')
password = params.get('DB', 'password')
db_port = params.get('DB', 'port')

### Flask Config ###
fk_host = params.get('Flask', 'host')
fk_port = params.get('Flask', 'port')

### Cups Config ###
qcnt = 0
cupsVersion = str(params.get('Cups', 'version'))
cupsUri = params.get('Cups', 'cupsUri')
tcUris = ast.literal_eval(params.get('Cups', 'tcUris'))
tcCredsDir = params.get('Cups', 'tcCredsDir')

LEND=b'\\s*\r?\n'
PEM_REX = re.compile(b'-+BEGIN (?P<key>[^-]+)-+' + LEND +
                    b'(([0-9A-Za-z+/= ]+' + LEND + b')+)' +
                    b'-+END (?P=key)-+' + LEND)

def normalizePEM(data:bytes, fmt="PEM") -> List[bytes]:
        norm = []
        for pem in PEM_REX.finditer(data):
            if fmt == "DER":
                out = base64.b64decode(re.sub(LEND, b'\n', pem.group(2)))
                #out += b'\x00' * (4-len(out)&3)
            else:
                out = re.sub(LEND, b'\n', pem.group(0))
            norm.append(out)
        return norm

def rdPEM(fn, fmt="PEM"):
        print(fn)
        if not os.path.exists(fn):
            return b'\x00'*4
        with open(fn,'rb') as f:
            return normalizePEM(f.read(), fmt)[0]

def rdToken(fn):
        print(fn)
        if not os.path.exists(fn):
            return b'\x00'*4
        with open(fn,'rb') as f:
            token = f.read().decode('ascii')
            return token.strip().encode('ascii') + b'\r\n'

def readTcCred(routerid, tcCredsDir, fmt="PEM"):
        tcTrust = rdPEM('%s/tc-%s/tc-%s.trust' % (tcCredsDir,routerid, routerid), fmt)
        tcCert = rdPEM('%s/tc-%s/tc-%s.crt' % (tcCredsDir,routerid, routerid), fmt)
        if tcCert == b'\x00\x00\x00\x00':
            tcKey = rdToken('%s/tc-%s/tc-%s.key' % (tcCredsDir,routerid, routerid))
        else:
            tcKey = rdPEM('%s/tc-%s/tc-%s.key' % (tcCredsDir,routerid, routerid), fmt)
        return tcTrust + tcCert + tcKey



def readRouterConfig(id, auth, d = {}) -> Dict[str,Any]:
    conn = db.connect(  
                db_host, 
                database, 
                user, 
                password,
                db_port
                )
    
    

    if "ERROR" not in str(conn):
        records = db.fetch(conn,"*", "gateway_data", "gateway_name = '"+id+"'")
        conn.close()

        d['cupsCred'] = records[0][2]
        d['tcCred'] = records[0][3]
        tcUri = str(records[0][4])
        #print(ah , cc)

        if d['cupsCred'] != auth:
            log ={
                    "code": 16,
                    "message": "error:unauthenticated (call was not authenticated)",
                    "details": [
                        {
                            "name": "unauthenticated",
                            "message_format": "call was not authenticated",
                            "code": 16
                        }
                    ]
                }
            
            logger.error(log)
            return log

        d['fwSig'] = [(b'', b'\x00'*4)]
        d['fwBin'] = ''
        d['version'] = cupsVersion
        d['cupsUri'] = cupsUri
        
        
        
        d['tcUri'] = tcUris.get(tcUri)
        
        with open('./config/versions.bin', 'rb') as f:
            fwBin = f.read()
        d['fwBin'] = fwBin
        
        

        with open('%s/tc-%s/tc-%s.key' % (tcCredsDir,tcUri,tcUri), 'w') as f:
            f.writelines("-----BEGIN EC PRIVATE KEY-----\n")
            f.writelines(auth.split(" ")[1])
            f.writelines("\n-----END EC PRIVATE KEY----")


        d['tcCred']   = readTcCred(tcUri, tcCredsDir, d.get("credfmt", "DER"))
        
        #d['cupsCredCrc'] = crc32(d['cupsCred']) & 0xFFFFFFFF
        d['tcCredCrc']   = crc32(d['tcCred'])   & 0xFFFFFFFF
        #print(d['tcCredCrc'])
        
    else:
        logger.error(conn)
        return conn
        
    return d
    
def encodeUri( key:str, req:Dict[str,Any], cfg:Dict[str,Any]) -> bytes:
    k = key+'Uri'
    if not cfg.get(k) or req[k] == cfg[k]:
        return b'\x00'
    s = cfg[k].encode('ascii')
    return struct.pack('<B', len(s)) + s

def encodeCred(key:str, req:Dict[str,Any], cfg:Dict[str,Any]) -> bytes:
    #return b'\x00\x00' ###For now###
    k = key+'CredCrc'
    if not cfg.get(k) or req[k] == cfg[k]:
        return b'\x00\x00'
    d = cfg[key+'Cred']
    return struct.pack('<H', len(d)) + d

def encodeFw(req:Dict[str,Any], cfg:Dict[str,Any]) -> bytes:
    if not cfg.get('version') or req['version'] == cfg['version']:
        logger.debug('  CUPS: No fw update required')
        return b'\x00\x00\x00\x00'
    fwbin = cfg['fwBin']
    return struct.pack('<I', len(fwbin)) + fwbin

def encodeSig(req:Dict[str,Any], cfg:Dict[str,Any]) -> Tuple[bytes, int]:
    return (b'\x00\x00\x00\x00',0) ###For now###
    if not cfg.get('version') or req['version'] == cfg['version']:
        return (b'\x00\x00\x00\x00',0)
    sc = req.get('keys')
    if sc is None:
        logger.debug('x CUPS: Request does not contain a signing key CRC!')
        return (b'\x00\x00\x00\x00',0)
    for (c,s) in cfg['fwSig']:
        for scn in sc:
            if c == int(scn):
                logger.debug('  CUPS: Found matching signing key with CRC %08X', c)
                return (struct.pack('<II', len(s)+4, c) + s, c)
    logger.debug('x CUPS: Unable to encode matching signature!')
    return (b'\x00'*4,0)

def on_response(r_cupsUri:bytes, r_tcUri:bytes, r_cupsCred:bytes, r_tcCred:bytes, r_sig:bytes, r_fwbin:bytes) -> bytes:
    return r_cupsUri + r_tcUri + r_cupsCred + r_tcCred + r_sig + r_fwbin

    
    #return r_cupsUri + r_tcUri + r_cupsCred + r_tcCred + r_sig + r_fwbin

#@app.errorhandler(401)
def custom_401(e):
    print(e)
    return jsonify(error=str(e)), 401

@app.route('/update-info')
def update_info():
    req = request.get_json()

    if request.headers.get('authorization'):
        auth = request.headers['authorization']
    else:
        fk_abort(401,description="Authentication Header Not Found")
    #print("HELLLLO",auth)


    routerid  = req['router']
    cfg = readRouterConfig(routerid, auth)
    if cfg.get("message") and "error" in cfg["message"]:
        return make_response(jsonify(cfg), 401)
    
    version = req.get('package')
    if not version:
        err = 'ERROR - CUPS: router '+ routerid +' reported null/unknown firmware!'
        logger.debug(err)
        return make_response(jsonify({"response": err}), 204)

    req['version'] = version
    cupsCrc   = req['cupsCredCrc']
    tcCrc     = req['tcCredCrc']
    cupsUri   = req['cupsUri']
    tcUri     = req['tcUri']
    
    r_cupsUri         = encodeUri ('cups', req, cfg)
    r_cupsCred        = encodeCred('cups', req, cfg)
    r_tcUri           = encodeUri ('tc'  , req, cfg)
    r_tcCred          = encodeCred('tc'  , req, cfg)
    (r_sig, r_sigCrc) = encodeSig(req, cfg)
    r_fwbin           = encodeFw(req, cfg)

    logger = logging.getLogger("cups-server")

    print(('< CUPS Response:\n' +
              '  cupsUri : {} {}\n' +
              '  tcUri   : {} {}\n' +
              '  cupsCred: {} bytes -- {}\n' +
              '  tcCred  : {} bytes -- {}\n' +
              '  sigCrc  : {}\n' +
              '  sig     : {} bytes\n' +
              '  fw      : {} bytes -- {}').format(
                r_cupsUri[1:], ("<- " if r_cupsUri[1:] else "-- ") + "[%s]" % cupsUri,
                 r_tcUri[1:], ("<- " if r_tcUri[1:] else "-- ") + "[%s]" % tcUri,
                 len(r_cupsCred)-2, ("[%08X] <- " % cfg['cupsCredCrc'] if len(r_cupsCred)-2 else "") + "[%08X]" % (cupsCrc),
                 len(r_tcCred)-2  , ("[%08X] <- " % cfg['tcCredCrc'] if len(r_tcCred)-2 else "") + "[%08X]" % (tcCrc),
                 r_sigCrc,
                 len(r_sig)-4, # includes CRC
                 len(r_fwbin)-4, ("[%s] <- " % cfg.get('version') if len(r_fwbin)-4 else "") + "[%s]" % (req['version'])))

    
    logger.info('< CUPS Response:\n' 
              '  cupsUri : %s %s\n' 
              '  tcUri   : %s %s\n'
              '  cupsCred: %3d bytes -- %s\n'
              '  tcCred  : %3d bytes -- %s\n'
              '  sigCrc  : %08X\n'
              '  sig     : %3d bytes\n'
              '  fw      : %3d bytes -- %s'
              ,  r_cupsUri[1:], ("<- " if r_cupsUri[1:] else "-- ") + "[%s]" % cupsUri,
                 r_tcUri[1:], ("<- " if r_tcUri[1:] else "-- ") + "[%s]" % tcUri,
                 len(r_cupsCred)-2, ("[%08X] <- " % cfg['cupsCredCrc'] if len(r_cupsCred)-2 else "") + "[%08X]" % (cupsCrc),
                 len(r_tcCred)-2  , ("[%08X] <- " % cfg['tcCredCrc'] if len(r_tcCred)-2 else "") + "[%08X]" % (tcCrc),
                 r_sigCrc,
                 len(r_sig)-4, # includes CRC
                 len(r_fwbin)-4, ("[%s] <- " % cfg.get('version') if len(r_fwbin)-4 else "") + "[%s]" % (req['version']))

    body = on_response(r_cupsUri, r_tcUri, r_cupsCred, r_tcCred, r_sig, r_fwbin)
    #print(body)
    return body



app.run(host = fk_host,port=fk_port)

