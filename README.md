## dcd.py - decoding base, binary, hex, etc from the terminal

#### Installation
`git clone <repo>`

___
#### Features
- base 2 (binary), 8 (octal), 10 (decimal), 16 (hex), 32, 58, 62, 64, 85, 91
- ascii encoding and base decoding
- append/ write to output `.txt` files

___
#### Usage
```
python3 dcd.py <base> -d/-e "input string" optional: -o/-O <output file>

>> Bases
-b2, --base2, --binary          <01100001>
-b8, --base8, --octal           <164 145 163 164>
-b10, --base10, --decimal       <116 101 115 116>
-b16, --base16, --hex           <74 65 73 74>
-b32, --base32                  <ORSXG5A=>
-b58, --base58                  <3yZe7d>
-b62, --base62                  <289lyu>
-b64, --base64                  <dGVzdA==>
-b85, --base85, --ascii85       <FCfN8>
-b91, --base91                  <fPNKd>
-u, --unicode                   <U+74 U+65 U+73 U+74>

>> Output
-o      <append to file>
-O      <overwrite file>
```

___
#### Later Additions
- maybe cipher decoding
