#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")
from de import RSADOAEP
from ORE import *
from cpabew import CPABEAlg
from web_client import get_de_key, get_ore_key, get_cpabe_pub_key, get_org_cpabe_secret, query_enc_data

import jsonlines
from tqdm import tqdm
import yaml
import re
from dateutil import parser
from datetime import datetime

from pprint import pprint
import traceback
import pickle

DEBUG_POLICY_PARCER = False

def _to_bool(st):
   trues = ["t","true", "True"]
   try:
      if type(st) == bool :
         return st
      if type(st) == str and st in trues:
         return True
      else:
         False
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      return False

def _str_to_epoch(some_time_str):
   # parse dates without knwoing format
   # https://stackoverflow.com/a/30468539/12044480
   t = parser.parse(some_time_str)
   unix = t.timestamp()
   print("Time:", t, "unix:",unix)
   return int(unix)

def load_yaml_file(f_name):
   with open(f_name) as f:
      print("Loading data from {}...".format(f_name))
      data = yaml.load(f, Loader=yaml.FullLoader)
   return data

def load_json_file(f_name):
   with jsonlines.open(f_name) as reader:
      print("Loading data from {}...".format(f_name))
      dat = list()
      for line in tqdm(reader):
         dat.append(line["data"])
   return dat


def match_re_to_keys(reg: str, keys: list):
   r = re.compile(reg)
   newlist = list(filter(r.match, keys))
   # if len(newlist) > 0:
   #    print("reg: {}".format(repr(reg)))
   #    print("OG keys: {}".format(keys))
   #    print("matched keys [{}]: {}".format(repr(reg),newlist))
   return newlist


def encrypt_as_de(dat,key):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "DE_encrypted"
   else:
      try:
         enc_alg = RSADOAEP(key_sz_bits=2048, rsa_pem=key)
         dat = str(dat).encode("UTF-8")
         return enc_alg.encrypt(dat)
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         return None
def encrypt_as_timestamp(dat,key):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "ORE_encrypted"
   else:
      try:
         dat = _str_to_epoch(dat)
         if type(dat) == int and dat > 0:
            return OREComparable.from_int(dat,key).get_cipher_obj().export()
         else:
            return None
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         return None
def encrypt_as_cpabe(dat, policy, pk):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "CPABE_encrypted_{}".format(policy.replace(' ',"_"))
   else:
      try:
         bsw07 = CPABEAlg()
         return bsw07.cpabe_encrypt_serialize(pk, str(dat).encode("UTF-8"), policy)
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         return None





def load_fetch_de_key(kms_url, DE_key_location):
   try:
      k = open(DE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         de_key = get_de_key(kms_url)
         if de_key == None:
            sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
         return de_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
      open(DE_key_location, "wb").write(de_key)
      return 
   sys.exit("Could not load or fetch DE key")

def load_fetch_ore_key(kms_url, ORE_key_location):
   try:
      k = open(ORE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_key = get_ore_key(kms_url)
         if ore_key == None:
            sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
         return ore_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
      open(ORE_key_location, "wb").write(ore_key)
      return 
   sys.exit("Could not load or fetch ORE key")

def load_fetch_cpabe_pk(kms_url, cpabe_pk_location):
   try:
      k = open(cpabe_pk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         pk_key = get_cpabe_pub_key(kms_url,debug=True)
         if pk_key == None:
            sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
         return pk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
      open(cpabe_pk_location, "wb").write(pk_key)
      return 
   sys.exit("Could not load or fetch CPABE Public Key")

def load_fetch_cpabe_sk(kms_url, name, cpabe_sk_location):
   try:
      k = open(cpabe_sk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         sk_key = get_org_cpabe_secret(kms_url,name)
         if sk_key == None:
            sys.exit("Could not fetch CPABE Public Key({}) from KMS server({})".format(name,kms_url))
         return sk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key({}) from KMS server({})".format(name,kms_url))
      open(cpabe_sk_location, "wb").write(sk_key)
      return 
   sys.exit("Could not load or fetch CPABE Secret Key({})".format(name))

def get_all_keys(kms_url, name, DE_key_location, ORE_key_location, cpabe_pk_location, cpabe_sk_location):
   de = load_fetch_de_key(kms_url,DE_key_location)
   ore = load_fetch_ore_key(kms_url,ORE_key_location)
   abe_pk = load_fetch_cpabe_pk(kms_url,cpabe_pk_location)
   abe_sk = load_fetch_cpabe_sk(kms_url,name, cpabe_sk_location)

   return {
            "de": de,
            "ore": ore,
            "pk": abe_pk,
            "sk": abe_sk
         }

if __name__ == "__main__":
   # todo: add arguemnt parser   
   #        force keep keys
   #     autoremove keys on exit

   config_f_name = "./config.yaml"#sys.argv[1] 

   config_collector = load_yaml_file(config_f_name)
   try:
      DEBUG = config_collector["debug"]["enabled"]
      if DEBUG:
         print("Debug: True.")
   except:
      DEBUG = False

   try:
      ONLY_ONE = config_collector["debug"]["process_only_one"]
   except:
      ONLY_ONE = False



   key_arguments = {
                     "kms_url": config_collector["kms"]["url"],
                     "name": config_collector["name"],
                     "DE_key_location": config_collector["key_files"]["de"],
                     "ORE_key_location": config_collector["key_files"]["ore"],
                     "cpabe_pk_location": config_collector["key_files"]["cpabe_pub"],
                     "cpabe_sk_location": config_collector["key_files"]["cpabe_secret"]
                    }
   keychain = get_all_keys(**key_arguments)


   if DEBUG:
      print("#"*21 +" config " + "#"*21)
      pprint(config_collector)
      print("#"*50)

   try:
      query = config_collector["query"]
      print("query:", query)

   except:
      sys.exit("query must be defined.")

   try:
      from_time = config_collector["from_time"]
      enc_from_time = encrypt_as_timestamp(from_time, keychain["ore"])
   except:
      enc_from_time = None
   try:
      to_time = config_collector["to_time"]
      enc_from_time = encrypt_as_timestamp(to_time, keychain["ore"])
   except:
      enc_to_time = None

   try:
      enc_val = encrypt_as_de(query, keychain["de"])
      print("enc_query:", enc_val)
      import base64
      print("enc_query base64:", base64.b64encode(enc_val))
   except:
      traceback.print_exc()
      sys.exit("Failed to encrypt '{}'".format(query))

   pickled_resp_data = query_enc_data(config_collector["backend_server"]["url"], enc_val, enc_from_time, enc_to_time, debug=DEBUG)
   resp_data = pickle.loads(pickled_resp_data)
   print("returned:")
   pprint(pickled_resp_data)
   print("unpickled:", resp_data)
   for record in resp_data:
      
      pprint(record)
      if ONLY_ONE:
         break






