import logging

import json
from math import e
from typing import Any,Dict,List,Tuple
import base64
import os
import struct
from uu import Error
from zlib import crc32
import re
import ast

import azure.functions as func
from . import db_class as db
import tempfile
from os import listdir

with open('local.settings.json') as lfile:
    localSettings = json.load(lfile)

for i in localSettings['Values']:
    os.environ[i] = localSettings['Values'][i]

db_host = os.environ['DB_HOST']
db_name = os.environ['DB_NAME']
db_user = os.environ['DB_USERNAME']
db_password = os.environ['DB_PASSWORD']
db_port = int(os.environ['DB_PORT'])
db_ssl_ca = os.environ['DB_SSL_CA']

# ### Flask Config ###
# fk_host = params.get('Flask', 'host')
# fk_port = params.get('Flask', 'port')





### Cups Config ###
cupsVersion = os.environ['VERSION']
cupsUri = os.environ['CUPSURI']
tcUris = ast.literal_eval(os.environ['TCURIS'])
tcCredsDir = os.environ['TCCREDSDIR']

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
        #logging.info(f"WEEEEEEEEE{fn}")
        token = fn.decode('ascii')
        #logging.info(f"TOKENNNNN{token}")
        return token.strip().encode('ascii') + b'\r\n'

def readTcCred(routerid, tcCredsDir, fp, fmt="PEM"):
        tcTrust = rdPEM('%s/tc-%s/tc-%s.trust' % (tcCredsDir,routerid, routerid), fmt)
        tcCert = rdPEM('%s/tc-%s/tc-%s.crt' % (tcCredsDir,routerid, routerid), fmt)
        if tcCert == b'\x00\x00\x00\x00':
            tcKey = rdToken(fp)
        else:
            tcKey = rdPEM(fp, fmt)
        logging.info("tcTrust: %s" % tcTrust)
        logging.info("tcCert: %s" % tcCert)
        logging.info("tcKey: %s" % tcKey)
        return tcTrust + tcCert + tcKey



def readRouterConfig(id, auth, records, d = {}) -> Dict[str,Any]:
    d['cupsCred'] = records[0][2]
    d['tcCred'] = records[0][3]
    tcUri = str(records[0][4])

    d['fwSig'] = [(b'', b'\x00'*4)]
    d['fwBin'] = ''
    d['version'] = cupsVersion
    d['cupsUri'] = cupsUri
    
    
    
    d['tcUri'] = tcUris.get(tcUri)

    try:
        with open('./config/versions.bin', 'rb') as f:
            fwBin = f.read()
        d['fwBin'] = fwBin

        tcCredsfile = tempfile.gettempdir()
        fp = tempfile.TemporaryFile()
        fp.write(b"-----BEGIN EC PRIVATE KEY-----\n")
        fp.write(str(auth.split(" ")[1]).encode('ascii'))
        fp.write(b"\n-----END EC PRIVATE KEY----")
        fp.seek(0)
        filesDirListInTemp = listdir(tcCredsfile)
        
        # tcCredsPath = '%s/tc-%s/tc-%s.key' % (tcCredsDir,tcUri,tcUri)
        # os.chmod(tcCredsPath, 0o777)
        # with open(tcCredsPath, 'w') as f:
        #     f.writelines("-----BEGIN EC PRIVATE KEY-----\n")
        #     f.writelines(auth.split(" ")[1])
        #     f.writelines("\n-----END EC PRIVATE KEY----")

    except (Exception, Error) as error:
        return {"ERROR":error}
    else:
        tcCreedsValues = fp.read()

    d['tcCred']   = readTcCred(tcUri, tcCredsDir, tcCreedsValues, d.get("credfmt", "DER"))
    
    d['tcCredCrc']   = crc32(d['tcCred'])   & 0xFFFFFFFF

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
        logging.debug('  CUPS: No fw update required')
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

def token_validation(id, auth):
    conn = db.connect(  
                db_host, 
                db_name, 
                db_user, 
                db_password,
                db_port,
                db_ssl_ca
                )

    if "ERROR" not in str(conn):
        records = db.fetch(conn,"*", "gateway_data", "gateway_name = '"+id+"'")
        conn.close()

        cupsCred = records[0][2]
        if cupsCred != auth:
            return "ERROR", "Authentication error: Invalid Credentials"
        else:
            return "SUCCESS", records

    else:
        return "DB_ERROR", "CUPS error: " + conn



def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    auth = req.headers.get("Authorization", None)
    if not auth:
        return func.HttpResponse(
            "Authentication error: Authorization header is missing",
            status_code=401
        )
    parts = auth.split()

    if parts[0].lower() != "bearer":
        return func.HttpResponse("Authentication error: Authorization header must start with ' Bearer'", status_code=401)
    elif len(parts) == 1:
        return func.HttpResponse("Authentication error: Token not found", status_code=401)
    elif len(parts) > 2:
        return func.HttpResponse("Authentication error: Authorization header must be 'Bearer <token>'", status_code=401)

    
    try:
        req_body = req.get_json()
    except ValueError as e:
            return func.HttpResponse(f"Request error: {e}", status_code=501)
    else:
        version = req_body.get('package')
        routerid = req_body.get('router')
    
    if not version:
        return func.HttpResponse(f"Cups error: router {routerid} reported null/unknown firmware.", status_code=400)

    res, desc = token_validation(routerid, auth)
    if "ERROR" not in res:
        pass
    elif "DB_ERROR" in res:
        return func.HttpResponse(desc, status_code=500)
    else:
        return func.HttpResponse(desc, status_code=403)

    cfg = readRouterConfig(routerid, auth, desc)

    if cfg.get('ERROR'):
        return func.HttpResponse(f"CUPS error: {cfg.get('ERROR')}", status_code=500)

    req_body['version'] = version
    cupsCrc   = req_body['cupsCredCrc']
    tcCrc     = req_body['tcCredCrc']
    cupsUri   = req_body['cupsUri']
    tcUri     = req_body['tcUri']


    r_cupsUri         = encodeUri ('cups', req_body, cfg)
    r_cupsCred        = encodeCred('cups', req_body, cfg)
    r_tcUri           = encodeUri ('tc'  , req_body, cfg)
    r_tcCred          = encodeCred('tc'  , req_body, cfg)
    (r_sig, r_sigCrc) = encodeSig(req_body, cfg)
    r_fwbin           = encodeFw(req_body, cfg)


    logging.info('< CUPS Response:\n' 
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
                 len(r_fwbin)-4, ("[%s] <- " % cfg.get('version') if len(r_fwbin)-4 else "") + "[%s]" % (req_body['version']))

    body = on_response(r_cupsUri, r_tcUri, r_cupsCred, r_tcCred, r_sig, r_fwbin)
    #print(body)
    return  func.HttpResponse(
             body,
             status_code=200
        )
