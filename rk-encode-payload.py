import argparse
import base64

def caesar_shift(payload_bytes, shift_by):
    shift_by = int(shift_by)
    print(f"[-]   Applying caesar shift of {shift_by}")
    shifted_bytes = []
    for b in payload_bytes:
        shifted_bytes.append((b + shift_by) & 0xff)

    return shifted_bytes

def xor(payload_bytes, xor_phrase):
    print(f"[-]   XORing payload with phrase: {xor_phrase}")

    # Get the list of ints represeting the xor phrase
    xor_key = list(bytes(xor_phrase, 'utf-8'))

    xor_bytes = []
    for i, b in enumerate(payload_bytes):
        xb = b ^ xor_key[i % len(xor_key)]
        xor_bytes.append(xb)
    return xor_bytes

def reverse(payload_bytes):
    print(f"[-]   Reversing payload")

    return list(reversed(payload_bytes))

def output(msg, var_to_output):
    print(f"[-]   {msg}")
    print(var_to_output)
    print("-" * 100)
    
def write_payload_to_file(path, payload):
    f = open(path, 'w')
    f.write(payload)
    f.close()
    
# The list of valid output formats
valid_formats = ['base64','hex','int']

# Parse the cmd line args        
parser = argparse.ArgumentParser(description='Encode a msfvenom payload')
parser.add_argument('--payload', help='The location of the payload to encode')
parser.add_argument('--transforms', help='The transforms to apply to the payload')
parser.add_argument('--format', help='The output format to produce', default="base64")
parser.add_argument('--wrap', type=int, help='The wrap length of the output', default=-1)
parser.add_argument('--wrapstr', help='The string to append to end of line before wrapping', default=None)
parser.add_argument('--pre', help='A string to prefix each character in the payload with', default='')
parser.add_argument('--post', help='A string to post-fix each character in the payload with', default='')
parser.add_argument('--join', help='A string to join each character in the payload with', default=',')
parser.add_argument('--output-file', help='The name of the file(s) to output the generated payloads to',default=None)

args = parser.parse_args()

# Parse the output formats & validate they are valid
output_fmts = args.format.split(',')
for fmt in output_fmts:
	if not fmt in valid_formats:
		print(f"[!] Format '{fmt}' is not valid")

# Check if we're outputing Base64, as this is handled separately
output_b64 = False
if 'base64' in output_fmts:
	output_b64 = True
	output_fmts.remove('base64')

# Read the payload file
payload_file = open(args.payload, 'r')
payload = payload_file.read()
payload_file.close()

print(f"[+] Read payload from file: {args.payload}")
print(f"[-]   Payload:")
print(payload)

# Payload should be in form: 0xf1, 0xf2, 0xd3 ... - split into array and remove the 0x
if (payload.startswith("[Byte[]] $buf = ")):
	payload = payload.replace("[Byte[]] $buf = ", "")
payload_bytes = payload.split(',')
parsed_bytes = []

for b in payload_bytes:
    b  = b.replace('0x', '')
    # We need 2-digit hex strings to convert
    if (len(b) < 2):
        # append leading 0
        b = '0' + b	
    parsed_bytes.append(int.from_bytes(bytes.fromhex(b)))

payload_bytes = parsed_bytes

# Now apply the transformations
print(f"[+] Transforms to apply {args.transforms}")
if args.transforms is not None:
	# Split transformation on comma
    transforms = args.transforms.split(",")
    for transform in transforms:
        tname = transform
        targ = None
        if ('=' in transform):
            parts = transform.split('=')
            tname = parts[0]
            targ = parts[1]

        if tname == 'caesar':
            payload_bytes = caesar_shift(payload_bytes, int(targ))
        elif tname == 'xor':
            payload_bytes = xor(payload_bytes, targ)
        elif tname == 'reverse':
            payload_bytes = reverse(payload_bytes)

print("[+] Transformed payloads:")

# Declare outputs dict with an output string for each output format
output_strs = { }
for fmt in output_fmts:
	output_strs[fmt] = ''

for i, b in enumerate(payload_bytes):
	for fmt in output_fmts:
		# If i > 0, append the join string to each array
		if i > 0 and args.join != None:
			output_strs[fmt] += args.join

		# Check if we should wrap the output
		if args.wrap > 0 and i > 0 and i % args.wrap == 0:
			# Append the wrapstr specified
			output_strs[fmt] += args.wrapstr + '\n'
	
		# Append prefix if supplied
		if args.pre != None:
			output_strs[fmt] += args.pre
			
		if fmt == 'hex':
			output_strs[fmt] += f'{b:x}'
		if fmt == 'int':
			output_strs[fmt] += str(b)
			
		if args.post != None:
			output_strs[fmt] += args.post

# Base64 encode
if output_b64:
	b64string = base64.b64encode(bytes(payload_bytes))
	b64output = b64string.decode('utf-8')
	output("Base64", b64output)
	if args.output_file != None:
		write_payload_to_file(f"{args.output_file}-b64.txt", b64output) 

for fmt in output_fmts:
	output(fmt, output_strs[fmt])
	if args.output_file != None:
		write_payload_to_file(f"{args.output_file}-{fmt}.txt", output_strs[fmt]) 
