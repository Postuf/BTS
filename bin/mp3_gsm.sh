#!/bin/bash
lame --decode $1.mp3 - | sox -v 0.5 -t wav - -t wav -b 16 -r 8000 -c 1 $1.wav
sox $1.wav -r 8000 -c 1 -t gsm $1.gsm
rm $1.wav

