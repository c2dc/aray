"""Shared constants for the aray pipeline."""

from pathlib import Path

BUILD_DIR = Path("build/linux")
BUILD_DIR_WIN = Path("build/windows")
BUILD_DIR_GENERIC = Path("build/generic")
DEFAULT_OFFSET_BASE = 0x3000
DEFAULT_OFFSET_STEP = 0x100
MINGW_GCC = "x86_64-w64-mingw32-gcc"
ELF_BASE = 0x400000  # standard non-PIE ELF load address
BANNER = "It's running.."
# Placeholder API key for gateways that ignore auth (e.g. local Ollama). The
# openai SDK refuses to construct a client without some api_key, even when the
# server never checks it.
DUMMY_API_KEY = "not-needed"

# Windows PE "string at offset" (runnable) path.
# A low-alignment PE (FileAlignment == SectionAlignment < 0x1000) is mapped flat
# by the loader, so file_offset == RVA — the PE analogue of the ELF linker trick.
PE_IMAGE_BASE = 0x140000000  # default MinGW x86-64 image base
PE_ALIGN = 0x10  # file alignment == section alignment (contiguous, flat mapping)
PE_OFFSET_SECTION = ".oray"  # COFF section (<=8 chars) holding offset-placed strings
# 8-byte sentinel used by the probe (pass 1) to locate where .oray data lands.
PE_SENTINEL = b"\xABarayS\xCD\xEF"
