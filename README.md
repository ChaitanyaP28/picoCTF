# PicoCTF

### USE THIS ONLY IF YOUR REALLY STUCK AND TIRED OF FINDING THE PASSWORD AND HAVE NO OTHER WAY.

## THIS IS THE LAST OPTION.

## Verify

```
for file in files/*; do   ./decrypt.sh "$file"; done
```


## Scan Suprise

Extract challenge.zip

Scan with QR Scanner


## Binary Search

Use this Python script:

```
low, high = 1, 1000

for _ in range(10):
    guess = (low + high) // 2
    print(guess)
    output = input()
    
    if "Higher" in output:
        low = guess + 1
    elif "Lower" in output:
        high = guess - 1

print("DONE")
```
**Example:**

![](</Pictures/BinarySearch1.png>)


## heap 0

See the addresses: `0x5bd0e822e2b0` and `0x5bd0e822e2d0`. It is 32 byte gap So inputting a string of length > 32 characters will modify the bico and we gain access to the flag.

```
2
```
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHELLO
```

![](</Pictures/heap0.png>)


## format string 0

The input 
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
Works because this leads to segmentation fault, which prints the flag.

![](</Pictures/formatstring0.png>)


## WebDecode


## Unminify


## Time Machine

Run this command on the folder where .git is present
```
git log --oneline
```


## Super SSH

Just Login

## endianness

Run the code then use this python script
```
def find_little_endian(word):
    # Reverse the string and convert each character to hexadecimal
    return "".join(f"{ord(c):02X}" for c in reversed(word))

def find_big_endian(word):
    # Convert each character to hexadecimal in order
    return "".join(f"{ord(c):02X}" for c in word)

# Example word from server
word = "weiwo"

# Compute endianness representations
little_endian = find_little_endian(word)
big_endian = find_big_endian(word)

print("Little Endian:", little_endian)
print("Big Endian:", big_endian)

```

![](</Pictures/endianness.png>)



# CanYouSee

Unzip the file

```
exiftool ukn_reality.jpg
```
![](Pictures/CanYouSee.png)

The Text is clearly a Base 64 Cipher

cGljb0NURntNRTc0RDQ3QV9ISUREM05fYjMyMDQwYjh9Cg==

This gives the flag



# Glory of the Garden

```
strings garden.jpg
```



# information

```
exiftool cat.jpg
```
![](Pictures/cat.png)

cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9

It is Base 64



# Secret of the Polyglot

```
foremost flag2of2-final.pdf
```

First part of flag in PNG image

Second part of the flag in the PDF (Open PDF in Chrome)



# Ph4nt0m 1ntrud3r

```
tshark -r myNetworkTraffic.pcap -Y "tcp.len!=8" -T fields -e frame.time -e tcp.segment_data | sort -k4 | awk '{print $6}' | xxd -p -r | base64 -d
```



# RED

```
zsteg red.png
```
cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==

Now put the data in Base64 decoder



# flags are stepic

```
curl http://standard-pizzas.picoctf.net:57324/
```

By asking AI which country doesnt exists gives us
```
Upanzi, Republic The
```

Download the png gives us a Very Large image of upz.png

run
```
stepic -d -i upz.png
```



# 