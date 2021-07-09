#!/usr/bin/env python3

import sys

sys.path.append("/priv-libs/libs")
from web_client import query_enc_data, test_auth
from priv_common import load_yaml_file, get_all_keys, encrypt_as_de, encrypt_as_timestamp, decrypt_record


import pickle, json
import argparse

from pprint import pprint
import traceback



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

   # print(keychain["sk"])
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
      enc_from_time = encrypt_as_timestamp(args.from_time, keychain["ore"], keychain["ore_params"])
      # print(enc_from_time,flush=True)
   except:
      # print("failed encrypt ore", flush=True)
      traceback.print_exc()
      sys.exit(f"Failed to encrypt timestamp {args.from_time} with ORE.")
      enc_from_time = None
   try:
      # to_time = config_queryc["to_time"]
      enc_to_time = encrypt_as_timestamp(args.to_time, keychain["ore"], keychain["ore_params"])
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
            print("  t <= {}".format(args.to_time))
         else:
            print("  t < {}".format(args.to_time))
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
                     sys.stdout.flush()
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

   





