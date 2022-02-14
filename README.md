# Can-Hax
Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets using can-utils which are available on most Linux variants.

Fingerprinting gives you a fingerprint which is a JSON of &lt;CAN ID&gt;:&lt;Can Payload Format&gt;

CAN payload template can be: 0=not observed in use, H=Hexadecimal values observed, N=Decimal values observed, so it looks something like 00NHHHHH.

Fuzzing uses cansend to push the frames over the wire.

For testing, I used ICSim at https://github.com/zombieCraig/ICSim

## Fingerprinting Usage:
Generate a CAN log with candump.

`candump vcan0 -l` 

Then run can-hax in fingerprint mode with the capture as the input file.

`can-hax --fingerprint --input icsim_capture.log -d "ICSIM Vehicle Simulator" -o icsim_fingerprint.V2.json`

## Fuzzing Usage:
Fuzz everything (might take a long time)

`can-hax --fuzz --input icsim_fingerprint.V2.json --can vcan0`

It might be better to test specific CAN IDs and you can specify that with --canid.

`can-hax --fuzz --canid 19B --input icsim_fingerprint.V2.json --can vcan0`

Adaptive Testing computes a metric for how complex the payload template is and uses a reduced set of possible values.

`can-hax --fuzz --adaptive --input icsim_fingerprint.V2.json --can vcan0`

You can also specify a reduced set of possible values with --quick or --superquick.

`can-hax --fuzz --quick --input icsim_fingerprint.V2.json --can vcan0`

