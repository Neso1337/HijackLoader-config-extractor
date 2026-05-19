# HijackLoader Config Extractor

A static config extractor for **HijackLoader** MSI samples, written in C. It parses the embedded IDAT chunks, reassembles and XOR-decrypts the compressed payload, decompresses it with LZNT1, then walks the internal module table to dump each embedded component's name, offset, and size.

## Usage

```
HijackLoader-config-extractor.exe <path_to_sample> [dump]
```

- `<path_to_sample>` — path to the HijackLoader MSI or payload file
- `dump` — optional flag; if provided, each embedded module is written to `module-dumps\`


Verified against 3 different HijackLoader samples (1 found in the wild, 2 from [MalwareBazaar](https://bazaar.abuse.ch/browse/tag/HijackLoader/)).