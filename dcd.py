#!/usr/bin/python3

import sys
import os

# organization type functions ------------------------------------------------------------------------------------------

py = ".\dcd"


def osd():
    global py
    if 'posix' in os.name:  # mac or linux - unix based
        py = "./dcd"


def banner():
    print('\n')
    print_green(r'     __       __      ___ ___')
    print_green(r' ___/ /______/ / _  _<  // _ \ ')
    print_green(r'/ _  / __/ _  / | |/ / // // /')
    print_green(r'\_,_/\__/\_,_/  |___/_(_)___/ ')
    print_green(r'<   -h or --help for usage   >')
    print('\n')


def usage():
    global py
    print_blue(f'\n[  Usage  ] \n{py} <base> -d, --decode/-e, --encode "input string"/.txt file optional: -o/-O <output file>\n'
               f'\n[  Example  ] \n{py} -b16 -e "test string" -o test.txt\n')
    bases = ['-b2, --base2, --binary \t\t<01100001>',
             '-b8, --base8, --octal \t\t<164 145 163 164>',
             '-b10, --base10, --decimal \t<116 101 115 116>',
             '-b16, --base16, --hex \t\t<74 65 73 74>',
             '-b32, --base32 \t\t\t<ORSXG5A=>',
             '-b58, --base58 \t\t\t<3yZe7d>',
             '-b62, --base62 \t\t\t<289lyu>',
             '-b64, --base64 \t\t\t<dGVzdA==>',
             '-b85, --base85, --ascii85 \t<FCfN8>',
             '-b91, --base91 \t\t\t<fPNKd>',
             '-u, --unicode \t\t\t<U+74 U+65 U+73 U+74>']
    out = ['-o \t<append to file>', '-O \t<overwrite file (with warning)>', '-Of \t<no warning force overwrite>']

    print_blue('>> Bases')
    max_len1 = max(len(s) for s in bases)
    column_width1 = max_len1 + 2

    for string in bases:
        print(string.ljust(column_width1))

    print_blue('\n>> Output')
    max_len2 = max(len(s) for s in out)
    column_width2 = max_len2 + 2

    for string in out:
        print(string.ljust(column_width2))
    print('\n')


def print_green(inpt):
    print('\033[0;32m' + inpt + '\033[0m')


def print_red(inpt):
    print('\033[0;31m' + inpt + '\033[0m')


def print_blue(inpt):
    print('\033[0;36m' + inpt + '\033[0m')


def output(func):
    def wrapper(*args, **kwargs):
        try:
            arg = list(args)
            result = func(*args, **kwargs)

            if arg[-2] == '-o':
                output_file = arg[-1]
                with open(output_file, 'a') as file:
                    file.write('\n' + result)
                result = '\n>>> ' + result
                result += f'\n[*] Result written to: {output_file}\n'

            elif arg[-2] == '-O':
                output_file = arg[-1]
                ask = input('\n[!] Overwrite? <y/n>: ')

                if ask.lower() == 'y':
                    with open(output_file, 'w') as file:
                        file.write('\n' + result)
                    result = '\n>>> ' + result
                    result += f'\n[*] Result written to: {output_file}\n'
                else:
                    print('\n[*] Use -o to append to file')
                    result = '>>> ' + result + '\n'
            elif arg[-2] == '-Of':
                output_file = arg[-1]
                with open(output_file, 'w') as file:
                    file.write('\n' + result)
                result = '\n>>> ' + result
                result += f'\n[*] Result written to: {output_file}\n'
            else:
                result = '\n>>> ' + result + '\n'
        except TypeError:
            print_red('[!] An unknown error occurred (likely a forgotten flag or input)')
            return None

        print(''.join(result))

    return wrapper

# init operation flags -------------------------------------------------------------------------------------------------


def op_list(*args):
    if not args:
        banner()
    else:
        currentArg = args[0]

        try:
            if currentArg in ('-b2', '--base2', '--binary'):
                b2(*args[1:])  # makes the wrapper function work instead of ignoring half the arguments
            elif currentArg in ('-b8', '--base8', '--octal'):
                print('Note: if result is unexpected, it may be because 2-bit chunks do not have a leading zero.'
                      ' If not, use --format <number>')
                b8(*args[1:])
            elif currentArg in ('-b10', '--base10', '--decimal'):
                b10(*args[1:])
            elif currentArg in ('-b16', '--base16', '--hex'):
                b16(*args[1:])
            elif currentArg in ('-b32', '--base32'):
                b32(*args[1:])
            elif currentArg in ('-b58', '--base58'):
                b58(*args[1:])
            elif currentArg in ('-b62', '--base62'):
                b62(*args[1:])
            elif currentArg in ('-b64', '--base64'):
                b64(*args[1:])
            elif currentArg in ('-b85', '--base85', '--ascii85'):
                b85(*args[1:])
            elif currentArg in ('-b91', '--base91'):
                b91(*args[1:])
            elif currentArg in ('-u', '--unicode'):
                uni(*args[1:])
            elif currentArg in ('-h', '--help'):
                usage()
            else:
                print_red('\n[!] Argument not recognized\n')
        except IndexError:
            print_red('\n[!] Missing information - decode/ encode flag or data string\n')

# base operation functions ---------------------------------------------------------------------------------------------


@output
def b2(operation, inpt, *_):  # *_ placeholder for the wrapper function cus it fully breaks without it
    if operation in ('-d', '--decode'):
        inpt = inpt.replace(' ', '')

        result = ''.join(
            chr(int(inpt[i * 8:i * 8 + 8], 2))  # convert 8-bit chunk to integer, then to character
            for i in range(len(inpt) // 8)  # iterate over 8-bit chunks
        )
        return result

    elif operation in ('-e', '--encode'):
        result = ' '.join(format(ord(i), '08b') for i in inpt)
        return result

    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b8(operation, inpt, *_):
    if operation in ('-d', '--decode'):
        inpt = inpt.replace(' ', '')

        result = ''.join(
            chr(int(inpt[i * 3:i * 3 + 3], 8))  # copied from base2, just swapped out the numbers
            for i in range(len(inpt) // 3)  # no shot it was this easy
        )
        return result
    elif operation in ('-e', '--encode'):
        result = ''.join(
            format(ord(char), '03o') for char in inpt)  # o for octal, 03 for three characters and leading 0 if needed
        result = ' '.join(result[i:i + 3] for i in range(0, len(result), 3))  # spaces every three numbers
        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b10(operation, inpt, *_):
    if operation in ('-d', '--decode'):
        inpt = inpt.split()

        result = ''.join(chr(int(val)) for val in inpt)
        return result
    elif operation in ('-e', '--encode'):
        result = ' '.join(str(ord(char)) for char in inpt)
        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b16(operation, inpt, *_):
    if operation in ('-d', '--decode'):
        inpt = inpt.replace(' ', '')

        result = ''.join(
            [chr(int(inpt[i:i + 2], 16))
             for i in range(0, len(inpt), 2)]
        )
        return result
    elif operation in ('-e', '--encode'):
        result = inpt.encode("utf-8").hex()
        result = ' '.join(result[i:i + 2] for i in range(0, len(result), 2))
        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b32(operation, inpt, *_):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    if operation in ('-d', '--decode'):
        # mapping from characters to their 5-bit values
        char_to_value = {char: i for i, char in enumerate(alphabet)}
        inpt = inpt.rstrip('=')

        bits = ''
        result = ''

        for char in inpt:
            # convert char 5-bit binary rep
            bits += format(char_to_value[char], '05b')
            # process 8-bit chunks > ASCII characters
            while len(bits) >= 8:
                byte = bits[:8]
                bits = bits[8:]
                result += chr(int(byte, 2))  # int = decimal -> chr = ascii

        return result
    elif operation in ('-e', '--encode'):
        chunks_8 = ''.join([format(bits, '08b') for bits in inpt.encode('utf8')])

        # divide into 5 bit chunks and append 0s if needed
        chunks_5 = [chunks_8[bits:bits + 5] for bits in range(0, len(chunks_8), 5)]
        padding = 5 - len(chunks_5[-1])  # length of last 5-bit chunk
        chunks_5[-1] += padding * '0'

        # map to alphabet
        result = ''.join([alphabet[int(bits, 2)] for bits in chunks_5])
        result += int(padding / 2) * '='

        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b58(operation, inpt, *_):  # ooo bitcoin

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    if operation in ('-d', '--decode'):
        ints = 0

        for char in inpt:
            ints = ints * 58 + alphabet.index(char)

        result = ints.to_bytes((ints.bit_length() + 7) // 8, byteorder='big')
        result = result.decode('utf-8')
        return result
    elif operation in ('-e', '--encode'):
        inpt = inpt.encode('utf-8')  # to bytes

        result = ''

        # bytes to int
        ints = int.from_bytes(inpt, byteorder='big')  # text to int, significant byte at the beginning of the array

        while ints > 0:
            # each char in alphabet maps to decimal val 0 - 57 so i just used the index or each char as a ref point
            # iteratively divide ints by 58 and use remainder to index
            ints, remainder = divmod(ints, 58)
            result = alphabet[remainder] + result

        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b62(operation, inpt, *_):
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    if operation in ('-d', '--decode'):  # plagiarized directly from my base58 code
        ints = 0

        for char in inpt:
            ints = ints * 62 + alphabet.index(char)

        result = ints.to_bytes((ints.bit_length() + 7) // 8, byteorder='big')
        result = result.decode('utf-8')
        return result
    elif operation in ('-e', '--encode'):
        inpt = inpt.encode('utf-8')

        result = ''

        # bytes to int
        ints = int.from_bytes(inpt, byteorder='big')  # text to int, significant byte at the beginning of the array

        while ints > 0:
            ints, remainder = divmod(ints, 62)
            result = alphabet[remainder] + result

        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b64(operation, inpt, *_):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    if operation in ('-d', '--decode'):
        # mapping from characters to their 5-bit values
        char_to_value = {char: i for i, char in enumerate(alphabet)}
        inpt = inpt.rstrip('=')

        bits = ''
        result = ''

        for char in inpt:
            # convert char 6-bit binary rep
            bits += format(char_to_value[char], '06b')
            # process 8-bit chunks > ASCII characters
            while len(bits) >= 8:
                byte = bits[:8]
                bits = bits[8:]
                result += chr(int(byte, 2))  # int = decimal -> chr = ascii

        return result
    elif operation in ('-e', '--encode'):
        # separate into 8 bit binary chunks
        chunks_8 = ''.join([format(bits, '08b') for bits in inpt.encode('utf8')])  # keep leading 0s

        # divide into 6 bit chunks and append 0s if needed
        chunks_6 = [chunks_8[bits:bits + 6] for bits in range(0, len(chunks_8), 6)]
        padding = 6 - len(chunks_6[-1])  # length of last 6-bit chunk
        chunks_6[-1] += padding * '0'

        # map to alphabet
        result = ''.join([alphabet[int(bits, 2)] for bits in chunks_6])
        result += int(padding / 2) * '='

        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def b85(operation, inpt, *_):
    # ascii chars 33 - 117
    alphabet = ''.join(chr(i) for i in range(33, 118))

    if operation in ('-d', '--decode'):  # plagiarized from b58 function, kinda surprised it worked first try
        ints = 0

        for char in inpt:
            ints = ints * 85 + alphabet.index(char)

        result = ints.to_bytes((ints.bit_length() + 5) // 4, byteorder='big')
        result = result.decode('utf-8')
        return result
    elif operation in ('-e', '--encode'):  # might be a slight issue w specific strings but I can't figure out what's wrong
        inpt_bytes = inpt.encode('utf-8')

        # padding input bytes with null bytes to make its length a multiple of 4
        while len(inpt_bytes) % 4 != 0:
            inpt_bytes += b'\x00'

        result = ""

        for i in range(0, len(inpt_bytes), 4):
            chunk = int.from_bytes(inpt_bytes[i:i + 4], 'big')

            encoded_chunk = ""
            for _ in range(5):
                encoded_chunk = alphabet[chunk % 85] + encoded_chunk
                chunk //= 85

            result += encoded_chunk
        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


# not done
@output
def b91(operation, inpt, *_):
    # ascii chars 33 - 126
    # alphabet = ''.join(chr(i) for i in range(33, 127))

    if operation in ('-d', '--decode'):
        print("\nImplementation in progress")
    elif operation in ('-e', '--encode'):
        '''inpt_bytes = inpt.encode('utf-8')
        result = ""
        val = 0
        bits = 0

        for byte in inpt_bytes:
            # bits - current position in combined value (val)
            # shift byte to the left by number specified by the value of bits
            # takes left shifted value, performs bitwise OR with the new value, and reassigns the value to val
            val |= byte << bits
            bits += 8

            if bits >= 13:
                # extracts lowest 13 bits from combined value (val), 8191 is a binary mask w 13 bits set to 1
                # this does a bitwise AND between val and 8191 and keeps the bits that are set to 1 in both
                chunk = val & 8191
                # right shifts val by 13 bits (discard bits used for current chunk)
                val >>= 13
                # updates the bit counter to reflect val change
                bits -= 13

                for _ in range(2):
                    result += alphabet[chunk % 91]
                    chunk //= 91

        if bits > 0:
            result += alphabet[val % 91]
        return result
        '''
        print("\nImplementation in progress")
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


@output
def uni(operation, inpt, *_):
    if operation in ('-d', '--decode'):
        inpt = inpt.replace('U+', '').strip

        result = ''.join(
            [chr(int(inpt[i:i + 2], 16))
             for i in range(0, len(inpt), 2)]
        )
        return result
    elif operation in ('-e', '--encode'):
        result = inpt.encode("utf-8").hex()
        result = ' U+'.join(result[i:i + 2] for i in range(0, len(result), 2))
        result = 'U+' + result  # for the first value
        return result
    else:
        print_red('\n[!] Incorrect flag provided (decode or encode only)\n')


if __name__ == '__main__':
    osd()
    op_list(*sys.argv[1:])
