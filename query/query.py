#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")
from de import RSADOAEP
from ORE import *
from cpabew import CPABEAlg
from web_client import get_de_key, get_ore_key,get_ore_params, get_cpabe_pub_key, get_org_cpabe_secret, query_enc_data, test_auth
from priv_common import load_yaml_file

from tqdm import tqdm
import re
from dateutil import parser as t_parser
from datetime import datetime
import pickle, json
import argparse

from pprint import pprint
import traceback


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
   # print(some_time_str)
   t = t_parser.parse(some_time_str)
   unix = t.timestamp()
   print("Time:", t, "unix:",unix)
   return int(unix)



def match_re_to_keys(reg: str, keys: list):
   r = re.compile(reg)
   newlist = list(filter(r.match, keys))
   # if len(newlist) > 0:
   #    print("reg: {}".format(repr(reg)))
   #    print("OG keys: {}".format(keys))
   #    print("matched keys [{}]: {}".format(repr(reg),newlist))
   return newlist


def encrypt_as_de(dat,key):
   try:
      enc_alg = RSADOAEP(key_sz_bits=2048, rsa_pem=key)
      dat = str(dat).encode("UTF-8")
      return enc_alg.encrypt(dat)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      traceback.print_exc()
      return None
# def encrypt_as_timestamp(dat,key):
#    try:
#       if dat == None:
#          return None
#       if type(dat) != int:
#          dat = _str_to_epoch(dat)
#       if type(dat) == int and dat > 0:
#          return OREComparable.from_int(dat,key).get_cipher_obj().export()
#       else:
#          return None
#    except KeyboardInterrupt:
#       raise KeyboardInterrupt
#    except:
#       traceback.print_exc()
#       return None

def encrypt_as_timestamp(dat,key, params, debug=False):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "ORE_encrypted"
   else:
      try:
         if type(dat) != int:
            dat = _str_to_epoch(dat)
         if type(dat) == int and dat > 0:
            cipher = OREcipher(key, params)
            return cipher.encrypt(dat)
         else:
            return None
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # if debug:
         #    traceback.print_exc()
         # traceback.print_exc()
         return None

def decrypt_cpabe(ciphertext, pk, sk):
   try:
      bsw07 = CPABEAlg()
      return bsw07.cpabe_decrypt_deserialize(pk, sk, ciphertext)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except Exception:
      # failed to decrypt
      return None
   except:
      traceback.print_exc()
      return None


def decrypt_record(record, pk, sk, debug=False):
   cpabe_keys = match_re_to_keys("cpabe_.*",record.keys())
   new_record = dict()
   for k in cpabe_keys:
      cipher = record[k]
      plain = pickle.loads(decrypt_cpabe(cipher, pk, sk))
      if plain:
         new_key = k[len("cpabe_"):]
         new_record[new_key] = plain
      elif debug:
         print("Failed to decrypt({}), wrong key for policy".format(k))

   return new_record


def load_fetch_de_key(kms_url,kms_access_key, DE_key_location, auth=None):
   try:
      k = open(DE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         de_key = get_de_key(kms_url,kms_access_key, auth=auth)
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

def load_fetch_ore_key(kms_url,kms_access_key, ORE_key_location, auth=None):
   try:
      k = open(ORE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_key = get_ore_key(kms_url,kms_access_key, auth=auth)
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

def load_fetch_ore_params(kms_url,kms_access_key, ORE_params_location, auth=None):
   try:
      k = open(ORE_params_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_key = get_ore_params(kms_url,kms_access_key, auth=auth)
         if ore_key == None:
            sys.exit("Could not fetch ORE parameters from KMS server({})".format(kms_url))
         return ore_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # traceback.print_exc()
         sys.exit("Could not fetch ORE parameters from KMS server({})".format(kms_url))
      open(ORE_params_location, "wb").write(ore_key)
      return 
   sys.exit("Could not load or fetch ORE parameters")

def load_fetch_cpabe_pk(kms_url,kms_access_key, cpabe_pk_location, auth=None):
   try:
      k = open(cpabe_pk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         pk_key = get_cpabe_pub_key(kms_url,kms_access_key,debug=True, auth=auth)
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

def load_fetch_cpabe_sk(kms_url, kms_access_key, cpabe_sk_location, auth=None):
   try:
      k = open(cpabe_sk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         sk_key = get_org_cpabe_secret(kms_url,kms_access_key, auth=auth)
         if sk_key == None:
            sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
         return sk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
      open(cpabe_sk_location, "wb").write(sk_key)
      return 
   sys.exit("Could not load or fetch CPABE Secret Key")

def get_all_keys(kms_url, kms_access_key, DE_key_location, ORE_key_location,ORE_params_location, cpabe_pk_location, cpabe_sk_location, auth=None):
   de = load_fetch_de_key(kms_url,kms_access_key,DE_key_location, auth=auth)
   ore = load_fetch_ore_key(kms_url,kms_access_key,ORE_key_location, auth=auth)
   ore_params = load_fetch_ore_params(kms_url,kms_access_key,ORE_params_location, auth=auth)
   abe_pk = load_fetch_cpabe_pk(kms_url,kms_access_key,cpabe_pk_location, auth=auth)
   abe_sk = load_fetch_cpabe_sk(kms_url,kms_access_key, cpabe_sk_location, auth=auth)

   return {
            "de": de,
            "ore": ore,
            "pk": abe_pk,
            "sk": abe_sk
         }


def create_parser():
   parser = argparse.ArgumentParser(description='Ship json file to collector.')

   parser.add_argument('query', metavar='QUERY', type=str,
                       help='query in plaintext')

   parser.add_argument('-q','--query-type', dest='query_type', 
                       default="search", nargs='?',
                       const="search" ,
                       choices=['search', 'count'],
                       help='Select type of query (default: %(default)s)')

   parser.add_argument('-f','--from-time', metavar='FROM', type=int,
                       default=None, dest='from_time',
                       help='integer epoch used as > filter for the query')

   parser.add_argument('-t','--to-time', metavar='TO', type=int,
                       default=None, dest='to_time',
                       help='integer epoch used as < filter for the query')

   parser.add_argument('-l','--left-inclusive', dest='left_inclusive', 
                       default=False, action="store_true",
                       help='modify the --from-time to be inclusive >= (default: off)')

   parser.add_argument('-r','--right-inclusive', dest='right_inclusive', 
                       default=False, action="store_true",
                       help='modify the --to-time to be inclusive <= (default: off)')

   
   return parser



if __name__ == "__main__":
   # todo: add arguemnt parser   
   #        force keep keys
   #     autoremove keys on exit

   parser = create_parser()
   args = parser.parse_args()

   # print(sys.argv)
   config_f_name = "/config.yaml"#sys.argv[1] 
   output_f_name = "/output"

   config_queryc = load_yaml_file(config_f_name)
   try:
      DEBUG = config_queryc["debug"]["enabled"]
      if DEBUG:
         print("Debug: True.")
   except:
      DEBUG = False

   try:
      ONLY_ONE = config_queryc["debug"]["process_only_one"]
   except:
      ONLY_ONE = False

# basic_auth = None
   try:
      basic_auth_user = config_queryc["basic_auth"]["user"]
      try:
         basic_auth_pass = config_queryc["basic_auth"]["pass"]
         basic_auth = (basic_auth_user, basic_auth_pass)
         print("Baic auth: enabled")
      except:
         exit("Baic auth: no password specified. Exiting.\n")
   except:
      print("Baic auth: disabled")
      basic_auth = None


   if basic_auth != None:
      if not test_auth(config_queryc["kms"]["url"], basic_auth):
         exit("Test failed: KMS basic auth. quiting.")
      if not test_auth(config_queryc["backend_server"]["url"], basic_auth):
         exit("Test failed: backend basic auth. quiting.")

   key_arguments = {
                     "kms_url": config_queryc["kms"]["url"],
                     "kms_access_key": config_queryc["kms_access_key"],
                     "DE_key_location": config_queryc["key_files"]["de"],
                     "ORE_key_location": config_queryc["key_files"]["ore"],
                     "ORE_params_location": config_queryc["key_files"]["ore_params"],
                     "cpabe_pk_location": config_queryc["key_files"]["cpabe_pub"],
                     "cpabe_sk_location": config_queryc["key_files"]["cpabe_secret"],
                     "auth": basic_auth
                    }
   keychain = get_all_keys(**key_arguments)

   print("sk[attribs]:", keychain["sk"]["S"])

   if DEBUG:
      print("#"*21 +" config " + "#"*21)
      pprint(config_queryc)
      print("#"*50)

   try:
      # query = config_queryc["query"]
      query = args.query
      print("query:", query)

   except:
      sys.exit("query must be defined.")

   try:
      # from_time = config_queryc["from_time"]
      enc_from_time = encrypt_as_timestamp(args.from_time, keychain["ore"])
   except:
      enc_from_time = None
   try:
      # to_time = config_queryc["to_time"]
      enc_to_time = encrypt_as_timestamp(args.to_time, keychain["ore"])
   except:
      enc_to_time = None

   if args.from_time or args.to_time:
      print("where:")
      if args.from_time:
         if args.left_inclusive:
            print("  t >= {}".format(args.from_time))
         else:
            print("  t > {}".format(args.from_time))
      if args.to_time:
         if args.right_inclusive:
            print("  t >= {}".format(args.to_time))
         else:
            print("  t > {}".format(args.to_time))
   try:
      enc_val = encrypt_as_de(query, keychain["de"])
      # print("enc_query:", enc_val)
      # import base64
      # print("enc_query base64:", base64.b64encode(enc_val))
   except:
      traceback.print_exc()
      sys.exit("Failed to encrypt '{}'".format(query))

   pickled_resp_data = query_enc_data(config_queryc["backend_server"]["url"], 
                           enc_val, args.query_type,
                           enc_from_time, enc_to_time,
                           args.left_inclusive,args.right_inclusive, debug=DEBUG, auth=basic_auth)

   # if DEBUG:
   #    sys.stdout.flush()

   if pickled_resp_data == None:
      sys.stderr.write("Failed to query server for data\n")
      sys.exit(1)

   resp_data = pickle.loads(pickled_resp_data)
   if DEBUG:
      print("returned:")
      pprint(pickled_resp_data)
      print("unpickled:", resp_data)

   if args.query_type == "search":
      try:
         with open(output_f_name, "w") as output_file:
            for record in resp_data:
               try:  
                  # pprint(record)
                  dec_record = decrypt_record(record, keychain["pk"], keychain["sk"], debug=DEBUG)
                  # print(record["cpabe_offset"])

                  if dec_record != {}:
                     output_file.write(json.dumps(dec_record)+'\n')
                  if DEBUG:
                     print(json.dumps(dec_record))
                  if ONLY_ONE:
                     break
               except:
                  traceback.print_exc()
                  sys.stdout.flush()
                  continue
      except:
         sys.stderr.write("Could not open output file.")
         sys.exit(1)
   elif args.query_type == "count":
      try:
         print("Count: {}".format(resp_data["count"]))
         with open(output_f_name, "w") as output_file:
            output_file.write("Count: {}\n".format(resp_data["count"]))

      except:
         sys.stderr.write("Bad response from server.")
         sys.exit(1)

   





