#include <Windows.h>
#include <stdio.h>


typedef NTSTATUS(WINAPI* fnRtlDecompressBuffer)(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);


int main(int argc, char* argv[])
{

	if (argc < 2)
	{
		printf("Usage: %s <path_to_file> [dump]\n", argv[0]);
		return 1;
	}


	int dump = (argc >= 3 && strcmp(argv[2], "dump") == 0);


	system("cls");

	HANDLE fileHandle;
	BYTE* rawBuffer;
	DWORD rawFileSize = 0;

	fileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		printf("[X] CreateFile failed: %i\r\n", GetLastError());
		return 0;
	}

	rawFileSize = GetFileSize(fileHandle, NULL);
	rawBuffer = (BYTE*)malloc(rawFileSize);


	if (!ReadFile(fileHandle, rawBuffer, rawFileSize, NULL, NULL))
	{
		printf("[X] ReadFile failed: %i\r\n", GetLastError());
		return 0;
	}

	printf("[*] Read file from disk    Size: %i\n", rawFileSize);

	printf("[*] buffer address: %p\n", rawBuffer);


	BYTE idatMarker[] = { 0x49, 0x44, 0x41, 0x54 };
	int chunkCount = 0;
	DWORD xorKey = 0;
	DWORD decompressedSize = 0;
	DWORD compressedSize = 0;
	BYTE* concatenatedBuffer = NULL;
	DWORD writeOffset = 0;

	for (size_t i = 0; i + 12 <= rawFileSize; i++)
	{
		BYTE* pos = rawBuffer + i;
		if (memcmp(pos + 4, idatMarker, 4) == 0)
		{
			DWORD chunkSize = _byteswap_ulong(*(DWORD*)pos);
			BYTE* data = pos + 8;

			if (!concatenatedBuffer)
			{
				if (*(DWORD*)data != 0xea79a5c6)
				{
					i += 8 + chunkSize + 4 - 1;
					continue;
				}
				xorKey = *(DWORD*)(data + 4);
				compressedSize = *(DWORD*)(data + 8);
				decompressedSize = *(DWORD*)(data + 12);
				concatenatedBuffer = (BYTE*)malloc(compressedSize + 16);
				printf("[*] First payload chunk at 0x%zx (size=0x%x) ", pos - rawBuffer, chunkSize);
				printf("    xorKey=0x%x compressed=0x%x decompressed=0x%x\n", xorKey, compressedSize, decompressedSize);
			}

			DWORD bytesToCopy = chunkSize;
			if (writeOffset + bytesToCopy > compressedSize + 16)
			{
				bytesToCopy = (compressedSize + 16) - writeOffset;
			}

			memcpy(concatenatedBuffer + writeOffset, data, bytesToCopy);
			writeOffset += bytesToCopy;
			i += 8 + chunkSize + 4 - 1;
			chunkCount++;
		}
	}
	printf("[*] Reassembled %d chunks (%u bytes)\n", chunkCount, writeOffset);

	for (size_t i = 0; i + 4 <= compressedSize; i += 4)
	{
		*(DWORD*)(concatenatedBuffer + 0x10 + i) ^= xorKey;
	}

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	fnRtlDecompressBuffer RtlDecompressBuffer = (fnRtlDecompressBuffer)GetProcAddress(hNtdll, "RtlDecompressBuffer");
	BYTE* decompressedBuffer = (BYTE*)malloc(decompressedSize);
	ULONG finalSize = 0;
	NTSTATUS status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, decompressedBuffer, decompressedSize, concatenatedBuffer + 0x10, compressedSize, &finalSize);

	if (status != 0)
	{
		printf("[!] Decompression failed: 0x%x\n", status);
	}
	else
	{
		printf("[*] Decompressed %u bytes\n", finalSize);
	}

	DWORD v13 = 0;

	if (decompressedBuffer[0x90] == 0)
	{
		v13 = *(DWORD*)(decompressedBuffer + 0x160);
	}
	DWORD offsetField = *(DWORD*)(decompressedBuffer + 8);
	BYTE* v18 = decompressedBuffer + offsetField + v13 + 0x3DD;

	DWORD moduleCount = *(DWORD*)(v18 + 0xEE4);
	BYTE* entries = v18 + 0x10DE;



	for (DWORD i = 0; i < moduleCount; i++)
	{
		BYTE* entry = entries + (i * 138);
		char* name = (char*)entry;
		DWORD dataOffset = *(DWORD*)(entry + 130);
		DWORD dataSize = *(DWORD*)(entry + 134);
		BYTE* moduleData = v18 + 0xEE4 + dataOffset;

		printf("    [*] %-32s offset=0x%08x  size=0x%08x\n", name, dataOffset, dataSize);

		if (dump)
		{
			CreateDirectoryA("module-dumps", NULL);
			char filename[256];
			snprintf(filename, sizeof(filename), "module-dumps\\dump-%s.bin", name);
			FILE* f = fopen(filename, "wb");
			fwrite(moduleData, 1, dataSize, f);
			fclose(f);
		}
	}

	DWORD keyDwords = *(DWORD*)(v18 + 0xCA4);
	DWORD blobSize = *(DWORD*)(v18 + 0xCA8);
	DWORD blobOffset = *(DWORD*)(v18 + 0xEEC);

	printf("[*] Encrypted PE blob at offset 0x%08x (size=0x%x) ", blobOffset, blobSize);
	printf("    keyDwords=%u keyBytes=0x%x\n", keyDwords, keyDwords * 4);

	BYTE* blob = v18 + 0xEE4 + blobOffset;
	DWORD* payloadKey = (DWORD*)blob;
	DWORD* encryptedPayload = (DWORD*)(blob + 4 * keyDwords);
	DWORD  encryptedSize = blobSize - 4 * keyDwords;
	DWORD  encDwords = encryptedSize / 4;

	for (DWORD i = 0; i < encDwords; i++)
	{
		encryptedPayload[i] ^= payloadKey[i % keyDwords];
	}

	printf("[*] Decrypted payload    Size: %u\n", encryptedSize);

	if (dump)
	{
		FILE* f = fopen("module-dumps\\dump-PAYLOAD.bin", "wb");
		if (f)
		{
			fwrite(encryptedPayload, 1, encryptedSize, f);
			fclose(f);
			printf("[*] Extracted final payload to dump-PAYLOAD.bin\n");
		}
	}
}