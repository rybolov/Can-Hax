#!/bin/python3

# Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets using can-utils
# which are available on most Linux variants.
# Fingerprinting gives you a fingerprint which is a JSON of <CAN ID>:<Can Payload Format>
# CAN payload template can be: 0=not observed in use, H=Hexadecimal values observed, N=Decimal values observed
# So it looks something like 00NHHHHH.
# Fuzzing uses cansend to push the frames over the wire.
# Michael Smith rybolov@rybolov.net


import argparse
import sys
import os
import re
import json
import shutil
import os
import datetime
import time

print("""
 _____                   _   _            
/  __ \                 | | | |           
| /  \/ __ _ _ __ ______| |_| | __ ___  __
| |    / _` | '_ \______|  _  |/ _` \ \/ /
| \__/\ (_| | | | |     | | | | (_| |>  < 
 \____/\__,_|_| |_|     \_| |_/\__,_/_/\_\\
Can-Hax: Fingerprint and fuzz CAN traffic.
""")

# #### Global variables #### #

# Assumes ID is 3 hexadecimal characters and payload is between 4 and 24 hexadecimal characters.
# compiled here so that we don't have to recreate it every time we use it in the loop below.
packet_re = re.compile("^[A-Fa-f0-9]{3}#[A-Fa-f0-9]{4,24}$")

# This was easier than recreating every single time.
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
hexes = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']


# #### Input validation, we loves it.... #### #
def valid_file(filename):
    print("Testing if", filename, "is a file.")
    # logging.info("Testing if %s is a file.", filename)
    if not os.path.isfile(filename):
        raise argparse.ArgumentTypeError("Not a valid file.")
    else:
        print(filename, "is most definitely a file.\n")
        return filename


parser = argparse.ArgumentParser(description='Can-Hax\nTools to fingerprint and fuzz Controller Area Network \
    (CAN) traffic.')
parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode. (default: none)')
parser.add_argument('--input', '-i', type=valid_file, help='File to use for input. (default: None)')
parser.add_argument('--output', '-o', help='Output file.  Required for --fingerprint. (default: None)')
parser.add_argument('--fingerprint', '-f', action='store_true''', help='Fingerprint based on a candump log. \
    (Requires input file) (default: none)')
parser.add_argument('--description', '-d', help='Description of the device. (Only used for --fingerprint) \
    (default: none)')
parser.add_argument('--fuzz', '-F', action='store_true', help='Fuzz a bus based on a fingerprint file. \
    (Requires input file) (default: none)')
parser.add_argument('--test', action='store_true', help='Test that the canutils exist and are executable. \
    (default: none)')
parser.add_argument('--can', '-c', help='Can Device.  Required for --fuzz. (default: none)')
parser.add_argument('--timing', '-t', default=20, help='Time delay in seconds per frame for --fuzz. (default: 20)')
args = parser.parse_args()


def test():
    if shutil.which('cansend') is None:
        print("Cannot find cansend, please verify that it's in your path.")
        exit(666)
    else:
        print('Found cansend. We can use this to send CAN packets.')

    if (args.fuzz or args.fingerprint) and not args.input:
        print('No input file specified with --input or -i.  Shutting down.')
        exit(666)

    if args.fuzz and not args.can:
        print('Fuzzing mode with no CAN device specified with --can or -c.  Shutting down.')
        exit(666)

    if args.fingerprint and not args.output:
        print('No output file specified with --output or -o.  Shutting down.')
        exit(666)


def main():
    test()
    if args.fingerprint:
        fingerprint()
    elif args.fuzz:
        fuzz()
    elif len(sys.argv) < 2:
        # print('No command specified, implying --help.\n')
        parser.print_help()
        exit(666)


def fingerprint():
    packets = []  # Raw payloads in HHH#HHHH... format, <ID>#<Payload>
    fingerprints = {}  # dictionary as {'HHH':'HHHH...', ...}, {ID:PayloadFormat, ...}
    canwrapper = {
        'description': args.description,
        'date': '',
        'version': '2',
        'fingerprints': {}
    }
    errorcount = 0

    f = open(args.input, 'r')
    lines = f.readlines()
    print('First 3 lines read in as:')
    for i in range(0, 3):
        print(lines[i], end='')
    print('')

    for line in lines:
        linelist = line.split()
        packet = linelist[2]  # Raw packet in HHH#HHHH... format, <ID>#<Payload>
        if re.match(packet_re, packet):
            canid, payload = packet.split("#")
        else:
            print('Error parsing payload.')
            print(packet)
            errorcount += 1
            if errorcount >= 5:
                print("Detected 5 payload errors in processing.  Are you sure this is a candump log?")
                exit(666)
        packets.append((canid, payload))  # tuples as ('HHH', 'HHHH...'), (<ID>, <Payload>)
    # We're using the last epoch timestamp in the capture file which is formatted in a string as (NNNNNNNNNN.NNNNNN)
    epochtime = linelist[0].replace('(', '')
    epochtime = epochtime.replace(')', '').split('.')
    epochtime = int(epochtime[0])  # We lose the miliseconds, but that's A-OK.
    datestamp = datetime.datetime.fromtimestamp(epochtime).strftime('%Y.%m.%d')
    print("Date of last log line:", datestamp)
    canwrapper['date'] = datestamp

    for packet in packets:  # 1st loop to get IDs and payload maximum lengths
        canid = packet[0]
        payload = packet[1]
        if id not in fingerprints.keys():
            fingerprints[canid] = ''.zfill(len(payload))
        elif len(fingerprints[canid]) < len(payload):
            fingerprints[canid] = ''.zfill(len(payload))

    for packet in packets:  # 2nd loop to get value formats, counting from the left
        canid = packet[0]
        payload = packet[1]
        # print(payload)
        for place in range(0, len(payload)):
            # print(fingerprints[canid][place])
            template = list(fingerprints[canid])
            if payload[place] != '0':  # If that character place is used
                if payload[place] not in numbers:  # Not a number, so we assume that it's A-F, or Hexadecimal
                    template[place] = 'H'
                elif template[place] != 'H':  # Don't downgrade from Hex to Decimal
                    template[place] = 'N'  # Default to Decimal
                # print(template)
                fingerprints[canid] = ''.join(template)

    print('Found', len(fingerprints.keys()), 'CAN IDs.')
    canwrapper['fingerprints'] = fingerprints
    print(json.dumps(canwrapper, indent=4, sort_keys=True))

    with open(args.output, 'w') as outfile:
        json.dump(canwrapper, outfile, indent=4)


def fuzz():
    parseerrors = 0
    with open(args.input) as inputfile:
        canwrapper = json.load(inputfile)
        fingerprints = canwrapper['fingerprints']
    for fingerprint in fingerprints:
        if not re.match("^[A-Fa-f0-9]{3}$", fingerprint):  # ID is 3 Hex characters
            parseerrors += 1
            print('CAN ID does not pass validation: ', fingerprint)
        if not re.match("^[0NH]{4,24}$", fingerprints[fingerprint]):  # Payload template is 2-24 characters of 0,N, or H
            parseerrors += 1
            print('CAN payload does not pass validation: ', fingerprints[fingerprint])
        if parseerrors >= 5:
            print('Too many errors, shutting down.')
            exit(666)
    if args.verbose:
        print('Found', len(fingerprints.keys()), 'CAN IDs.')
        print(json.dumps(fingerprints, indent=4, sort_keys=True))
    for canid in fingerprints:
        fuzzmatrix = []
        for character in fingerprints[canid]:
            if character == '0':
                fuzzmatrix.append([0])
            elif character == 'N':
                fuzzmatrix.append(numbers)
            elif character == 'H':
                fuzzmatrix.append(hexes)
            else:
                print('Unable to complete matrix.  I got the character', character)
                exit(666)
        if args.verbose:
            print('CanID:', canid)
            print('Fingerprint:', fingerprints[canid])
            print('Fuzz Matrix', fuzzmatrix)
        sendpacket(canid, 0, fuzzmatrix)


def sendpacket(canid, level, matrix):
    if args.verbose:
        print('Starting fuzz run. Level:', level)
        print('Matrix:', matrix)
    for character in matrix[level]:
        if level != len(matrix) -1:
            newlevel = level + 1
            matrix[level] = str(character)
            sendpacket(canid, newlevel, matrix)
        else:
            matrix[level] = str(character)
            canframe = canid + '#' + ''.join(matrix)
            print('Sending CAN frame: ', canframe)
            cansend = 'cansend ' + args.can + ' ' + canframe
            os.system(cansend)
            time.sleep(args.timing)
    return

if __name__ == '__main__':
    main()
