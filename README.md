# HijackLoader Config Extractor

A static config extractor for **HijackLoader** MSI samples, written in C. The MSI drops 2 non-PE files, the bigger of which contsins the configuration. The tool parses the embedded IDAT chunks, reassembles and XOR-decrypts the compressed payload, decompresses it with LZNT1, then walks the internal module table to dump each component's name, offset, and size. 

It also dumps the final payload delivered by the loader, into `module-dumps\dump-PAYLOAD.bin`, which can be found after the last module in the configutation file in it's encrypted stage.

## Usage

```
HijackLoader-config-extractor.exe <path_to_config> [dump]
```

- `<path_to_sample>` — path to the HijackLoader configuration file
- `dump` — optional flag; if provided, each embedded module and the final payload is written to `module-dumps\`


Verified against 3 different HijackLoader samples (1 found in the wild, 2 from [MalwareBazaar](https://bazaar.abuse.ch/browse/tag/HijackLoader/)).