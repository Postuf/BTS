## Description

This is the easy-to-deploy GSM network based on 2 LimeSDR whose main purpose is working in tandem with radio jammer to collect all mobile devices in near surrounding. Radius depending on power of applied jammer and can reach 100-200 meters.

## Requirements

- 8 cores hardware
- clean Ubuntu 20.04.3 LTS (not tested on other versions/distributions)
- 2 x [LimeSDR](https://limemicro.com/products/boards/limesdr/)
- preconfigured jammer with satisfying power
  - must cover all 3G, 4G downlink entirely (uplink unnecessary)
  - must cover all 2G downlink higher than 926MHz 
  - must NOT cover range 820-926MHz (GSM-850 uplink+downlink, E-GSM-900 downlink+uplink)

#### Jammer remarks

1. It is possible to use unconfigured(stock) jammer. In that case only devices which able to scan GSM-850 range by default will be collected.
2. It is possible not to use jammer at all. In that case only devices which could not connect to any other mobile network will be collected.
3. Jammer configuration is aimed to european region. In case of any other region you will have to perform radio investigation yourself in order to select right frequency ranges.

## How it works?

1. It deploys 2 GSM BTS
   1. first is broadcasting on E-GSM-900 (925.2MHz) **[bait BTS]**
   2. second is broadcasting on GSM-850 (869MHz)    **[true BTS]**
2. After manual running configured jammer and waiting 0.5-2 minutes most of the surrounding mobile devices connect to GSM network
3. Moves first BTS to GSM-850 on frequency 871MHz (near to the second one). **Bait turns into True BTS.**
4. Distributes subscribers equally between 2 true BTS.
5. Calls/sms subscribers.

#### What is "bait BTS"?

Bait BTS - is temporarily BTS which is needed for "european" devices to discover our GSM network. Some of devices (mostly iPhones) are not scanning "american" GSM-850 frequency range by default - they need a lot of time (up to 30 minutes) to switch in "american mode". In order to speed this up "bait BTS" was introduced: it sends out to devices the "true" neighbour BTS on "american" frequency (second BTS) so devices save it to cache and use it when "bait BTS" dissappears from E-GSM-900 and appears on GSM-850.

## Installation

```
./install <serial-of-first-LimeSDR> <serial-of-second-LimeSDR>
```

`serial-of-first-LimeSDR` - serial number of LimeSDR for "true" BTS  
`serial-of-second-LimeSDR` - serial number of LimeSDR for "bait" BTS

That is it.  
After installation you should be able to find new **mobile network "250 98"** and see 2 active BTS (via HackRF or any other SDR).  

1. True BTS on GSM-850
![True BTS](https://habrastorage.org/r/w1560/getpro/habr/upload_files/480/dad/ce7/480dadce7d2a1469ae3b8b6634543e3a.png)
2. Bait BTS on E-GSM-900 with enabled preconfigured jammer
![Bait BTS](https://habrastorage.org/r/w1560/getpro/habr/upload_files/7d5/97b/167/7d597b167967c951c49842b75024e6c7.png)

Stack of BTS services is going to start automatically each time system reboots. 

## Usage

After successful installation you can interact with GSM network via [sdrconsole.py](./bin/sdrconsole.py) script only.

#### Examples

List of connected subscribers:

```
sdrconsole.py show
```

Move "bait BTS" from E-GSM-900 to GSM-850 (turn into "true BTS"):

```
sdrconsole.py 850
```

Call to all subscribers:

```
sdrconsole.py call <from-number> voice mp3 <full-path-to-mp3-file> all
```

SMS to all subscribers:

```
sdrconsole.py sms normal [once/spam] <from> <text> all
```

Start/stop BTS stack:

```
sdrconsole.py start
sdrconsole.py stop
```

These are basic cases. For more information use built-in help:

```
sdrconsole.py --help
```

## Limitations

- unlimited connected subscribers
- 72 parallel calls
- 384 parallel SMS

## Roadmap

1. Wrap into Docker
