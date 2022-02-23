# Can-Hax
Can-Hax is a utility to fingerprint and fuzz Controller Area Network (CAN) packets/frames using can-utils which are available on most Linux variants.

For testing, I used ICSim at https://github.com/zombieCraig/ICSim

Fingerprinting gives you a fingerprint which is a JSON of &lt;CAN ID&gt;:&lt;Can Payload Format&gt;.  I put an example of a fingerprint of ICSim in this project as icsim_fingerprint.V2.json that you can use to compare output.

CAN payload template can be: 0=not observed in use, H=Hexadecimal values observed, N=Decimal values observed, so it looks something like 00NHHHHH.

Fuzzing uses cansend to push the frames over the wire.

## Setup for ICSim:
You will need cansend which is part of the can-utils package.  You can grab it on a Debian-based system with:

`sudo apt-get install can-utils build-essential libsdl2-dev libsdl2-image-dev`

The ICSim project comes with a simple shell script setup_vcan.sh which installs the appropriate kernel modules and creates a virtual CAN device at vcan0 which you can then use to send and receive CAN frames.  It also has an Instrument Cluster (vehicle dashboard) which you can use to view if your fuzzing makes any noticeable changes to the simulated vehicle (tip: try fuzzing CAN IDs 244, 19B, and 188).

`git clone https://github.com/zombieCraig/ICSim.git`

`cd ICSim`

`bash ./setup_vcan.sh`

`make`

`./icsim vcan0 &`

Can-utils also gives you cansniffer and candump which you can use to see what Can-Hax is doing.

`cansniffer -c vcan0`

`candump -c vcan0`

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

