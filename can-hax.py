#!/bin/python3

# Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets.
# Michael Smith rybolov@rybolov.net


import argparse
import sys
import os

# Input validation, we loves it....
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

if args.fingerprint:
    f = open(args.input, 'r')
    lines = f.readlines()
    print('First 3 lines read as:')
    for i in range(0,3):
        print(lines[i], end= '')












if __name__ == '__main__':
    pass
