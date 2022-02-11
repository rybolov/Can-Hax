Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets using can-utils which are available on most Linux variants.
Fingerprinting gives you a fingerprint which is a JSON of <CAN ID>:<Can Payload Format>
CAN payload template can be: 0=not observed in use, H=Hexadecimal values observed, N=Decimal values observed, so it looks something like 00NHHHHH.
Fuzzing uses cansend to push the frames over the wire.

Fingerprinting Usage:
./can-hax --fingerprint --input icsim_capture.log -d "ICSIM Vehicle Simulator" -o icsim_fingerprint.V2.json

Fuzzing Usage:
./can-hax --fuzz -v --input icsim_fingerprint.V2.json --can vcan0
