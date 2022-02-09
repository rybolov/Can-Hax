#!/bin/python3

# Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets.
# Michael Smith rybolov@rybolov.net


import argparse
import sys
import os
import re
import json

##### Global variables #####

# Assumes ID is 3 Hexadecimal characters and has between 4 and 24 characters in the payload.
#compiled here so that we don't have to recreate it every time we use it in the loop below.
packet_re = re.compile("^[A-F,a-f,0-9]{3}#[A-F,a-f,0-9]{4,24}$")

numbers = ['0','1','2','3','4','5','6','7','8','9']

##### Input validation, we loves it.... #####
def valid_file(filename):
    print("Testing if", filename, "is a file.")
    # logging.info("Testing if %s is a file.", filename)
    if not os.path.isfile(filename):
        raise argparse.ArgumentTypeError("Not a valid file.")
    else:
        print(filename, "is most definitely a file.\n")
        return filename

parser = argparse.ArgumentParser(description='Can-Hax\nTools to fingerprint and fuzz Controller Area Network (CAN) traffic.')
parser.add_argument('--input', '-i', type=valid_file, help='File to use for input. (default: None)')
parser.add_argument('--output', '-o', help='Output file. (default: None)')
parser.add_argument('--fingerprint', '-f', action='store_true''', help='Fingerprint based on a candump log. (Requires input file) (default: none)')
parser.add_argument('--fuzz', '-F', action='store_true', help='Fuzz a bus based on a fingerprint file. (Requires input file) (default: none)')
parser.add_argument('--test', '-t', action='store_true', help='Test that the canutils exist and are executable. (default: none)')
args = parser.parse_args()

if len(sys.argv) <2:
    # print('No command specified, implying --help.\n')
    parser.print_help()
    exit(666)

if (args.fuzz or args.fingerprint) and not args.input:
    print('No input file specified with --input or -i.  Shutting down.')
    exit(666)

if (args.fingerprint) and not args.output:
    print('No output file specified with --output or -o.  Shutting down.')
    exit(666)


if args.fingerprint:
    packets = [] # Raw payloads in HHH#HHHH... format, <ID>#<Payload>
    fingerprints = {} # dictionary as {'HHH':'HHHH...', ...}, {ID:PayloadFormat, ...}
    errorcount = 0

    f = open(args.input, 'r')
    lines = f.readlines()
    print('First 3 lines read in as:')
    for i in range(0,3):
        print(lines[i], end= '')
    print('')

    for line in lines:
        linelist = line.split()
        packet = linelist[2] # Raw packet in HHH#HHHH... format, <ID>#<Payload>


        if re.match(packet_re, packet):
            id,payload = packet.split("#")
        else:
            print('Error parsing payload.')
            print(id)
            errorcount +=1
            if errorcount >= 5:
                print("Detected 5 payload errors in processing.  Are you sure this is a candump log?")
                exit(666)
        packets.append((id, payload)) # tuples as ('HHH', 'HHHH...'), (<ID>, <Payload>)

    for packet in packets: #1st loop to get IDs and payload maximum lengths
        id = packet[0]
        payload = packet[1]
        if id not in fingerprints.keys():
            zeroes = len(payload)
            fingerprints[id] = ''.zfill(len(payload))
        elif len(fingerprints[id]) < len(payload):
            fingerprints[id] = ''.zfill(len(payload))

    for packet in packets:  # 2nd loop to get get value formats, counting from the left
        id = packet[0]
        payload = packet[1]
        # print(payload)
        for place in range(0,len(payload)):
            # print(fingerprints[id][place])
            template = list(fingerprints[id])
            if payload[place] != '0': # If that character place is used
                if payload[place] not in numbers: # Not a number so we assume that it's A-F, or Hexadecimal
                    template[place] = 'H'
                elif template[place] != 'H': # Don't downgrade from Hex to Decimal
                   template[place] = 'N' # Default to Decimal
                # print(template)
                fingerprints[id] = ''.join(template)

    print('Found', len(fingerprints.keys()), 'CAN IDs.')
    print(json.dumps(fingerprints, indent=4, sort_keys=True))

    with open(args.output, 'w') as outfile:
        json.dump(fingerprints, outfile, indent=4)












if __name__ == '__main__':
    pass
