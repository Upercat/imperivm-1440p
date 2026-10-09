// Native 1440p patcher for Imperivm III HD gbr.exe, revision r7.
//
// Writes a patched copy of the official HD executable. Every site is checked
// against its original bytes before it is written, and the result is compared
// with the reference SHA-256. It then writes DATA\CONST.INI with 2560x1440 in
// the resolution list. Built with a static CRT (see build.bat), so the
// resulting 1440p_patch.exe runs on a clean Windows installation.
//
// Usage:
//   1440p_patch.exe <gbr.exe> [output.exe] [--force]
//   1440p_patch.exe --identify <exe>
//
// Dropping gbr.exe onto 1440p_patch.exe writes gbr_1440p.exe next to it.

#define _CRT_SECURE_NO_WARNINGS  // _wfopen results are checked explicitly
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <clocale>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

constexpr const char* kVanillaSha256 = "72b09d1abd4f311efe4213a9a1110185519bde4db4ee57769d346b475c748473";
constexpr const char* kPatchedSha256 = "c8617691bb53910eb1648e070720a558ca29cf4251ebf523da17d97c9e564306";
constexpr const wchar_t* kDefaultOutputName = L"gbr_1440p.exe";
constexpr int kWidth = 2560;
constexpr int kHeight = 1440;

constexpr uint32_t kImageBase = 0x00400000;
constexpr uint32_t kTextRawBegin = 0x1000;
constexpr uint32_t kTextRawEnd = 0x3AB000;

// Original zoom-map column storage in .data BSS.
constexpr uint32_t kOldActive = 0x009D2CE0;   // g_apViewportColumnsActive: 2048 x 4 bytes
constexpr uint32_t kOldData = 0x009D4CE0;     // g_abViewportColumnData: 2048 x 16-byte vectors
constexpr uint32_t kOldGuard = 0x009DCCE0;    // static-init guard flags, also the data end marker
constexpr uint32_t kOldColumns = 0x800;
constexpr uint32_t kColumns = 0x1000;         // new zoom-map column capacity

constexpr char kCodeSectionName[8] = {'.', 'h', 'i', 'r', 'e', 's', 't', '\0'};
constexpr uint32_t kCodeSectionCharacteristics = 0x60000020;  // code, execute, read
constexpr uint32_t kCodeSectionVa = 0x00A95000;               // the stubs below use absolute addresses inside it
constexpr uint32_t kCodeSectionSize = 0x1000;
constexpr char kBssSectionName[8] = {'.', 'z', 'm', 'c', 'o', 'l', 's', '\0'};
constexpr uint32_t kBssSectionCharacteristics = 0xC0000080;   // uninitialized data, read, write

// .hirest contents. Absolute targets: main window object 0x00A87344,
// COSWindow::SetRect 0x00651870, inner WinMain 0x0074D590, IAT InvalidateRect
// 0x007AB308, GetModuleHandleA 0x007AB180, GetProcAddress 0x007AB10C,
// ClipCursor 0x007AB2C4, GetWindowRect 0x007AB2B4, GetForegroundWindow 0x007AB2E0.
struct Stub {
  uint32_t offset;
  const char* code;
};

constexpr Stub kHirest[] = {
    // RepaintStub: InvalidateRect(hwnd, NULL, FALSE); test byte [esi+0x134], 8; ret
    {0x00, "6a 00 6a 00 ff 76 60 ff 15 08 b3 7a 00 f6 86 34 01 00 00 08 c3"},
    // DpiStub: SetProcessDPIAware through GetModuleHandleA/GetProcAddress, then jmp inner WinMain
    {0x20, "68 50 50 a9 00 ff 15 80 b1 7a 00 85 c0 74 12 68 60 50 a9 00 50 ff 15 0c b1 7a 00 85 c0 74 02 "
           "ff d0 e9 4a 85 cb ff"},
    {0x50, "75 73 65 72 33 32 2e 64 6c 6c 00"},                           // "user32.dll"
    {0x60, "53 65 74 50 72 6f 63 65 73 73 44 50 49 41 77 61 72 65 00"},  // "SetProcessDPIAware"
    // ClipStub: shrink a non-NULL rectangle to the game area, then jmp [ClipCursor]
    {0x80, "8b 54 24 04 85 d2 74 40 8b 0d 44 73 a8 00 85 c9 74 36 66 8b 41 14 66 3b 41 10 7e 2c 66 8b 41 16 "
           "66 3b 41 12 7e 22 0f bf 41 14 03 02 40 89 42 08 0f bf 41 16 03 42 04 40 89 42 0c 0f bf 41 10 01 "
           "02 0f bf 41 12 01 42 04 ff 25 c4 b2 7a 00"},
    // ReclipStub: COSWindow::SetRect, then re-clip when the game window is in the foreground; ret 8
    {0xE0, "ff 74 24 08 ff 74 24 08 e8 83 c7 bb ff 50 ff 15 e0 b2 7a 00 8b 0d 44 73 a8 00 85 c9 74 1d 3b 41 "
           "60 75 18 83 ec 10 54 50 ff 15 b4 b2 7a 00 85 c0 74 06 54 e8 68 ff ff ff 83 c4 10 58 c2 08 00"},
};

struct KnownBuild {
  const char* sha256;
  const char* description;
};

constexpr KnownBuild kKnownBuilds[] = {
    {kVanillaSha256, "vanilla official HD gbr.exe (unpatched)"},
    {"71cf90f03e8903e5a7afd5e1083b542d4053bc99fee048887bb0b412074f9679",
     "earlier 1440p patch (arrays over GameSpy code, RWX .text)"},
    {kPatchedSha256, "1440p patch r7"},
};

class Failure : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

std::string Format(const char* format, ...) {
  char buffer[512];
  va_list args;
  va_start(args, format);
  std::vsnprintf(buffer, sizeof buffer, format, args);
  va_end(args);
  return buffer;
}

std::string Narrow(const std::wstring& text) {
  int size = WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string result(size > 0 ? size - 1 : 0, '\0');
  if (size > 1) WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1, &result[0], size, nullptr, nullptr);
  return result;
}

std::string HexBytes(const uint8_t* data, size_t length) {
  std::string text;
  for (size_t i = 0; i < length; ++i) text += Format(i ? " %02x" : "%02x", data[i]);
  return text;
}

std::string Sha256Hex(const std::vector<uint8_t>& data) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  uint8_t digest[32] = {};
  NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (BCRYPT_SUCCESS(status)) status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
  if (BCRYPT_SUCCESS(status))
    status = BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
  if (BCRYPT_SUCCESS(status)) status = BCryptFinishHash(hash, digest, sizeof digest, 0);
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!BCRYPT_SUCCESS(status)) throw Failure("SHA-256 computation failed");
  std::string text;
  for (uint8_t byte : digest) text += Format("%02x", byte);
  return text;
}

const char* DescribeBuild(const std::string& sha256) {
  for (const KnownBuild& build : kKnownBuilds)
    if (sha256 == build.sha256) return build.description;
  return nullptr;
}

std::vector<uint8_t> ReadFile(const std::wstring& path) {
  FILE* file = _wfopen(path.c_str(), L"rb");
  if (!file) throw Failure("cannot open " + Narrow(path));
  std::vector<uint8_t> data;
  uint8_t chunk[1 << 16];
  size_t count;
  while ((count = std::fread(chunk, 1, sizeof chunk, file)) > 0) data.insert(data.end(), chunk, chunk + count);
  bool failed = std::ferror(file) != 0;
  std::fclose(file);
  if (failed) throw Failure("cannot read " + Narrow(path));
  return data;
}

void WriteFile(const std::wstring& path, const std::vector<uint8_t>& data) {
  FILE* file = _wfopen(path.c_str(), L"wb");
  if (!file) throw Failure("cannot create " + Narrow(path));
  bool failed = std::fwrite(data.data(), 1, data.size(), file) != data.size();
  failed = (std::fclose(file) != 0) || failed;
  if (failed) {
    _wremove(path.c_str());
    throw Failure("cannot write " + Narrow(path));
  }
}

std::vector<uint8_t> ParseHex(const char* text) {
  std::vector<uint8_t> bytes;
  for (const char* p = text; *p;) {
    if (*p == ' ') {
      ++p;
      continue;
    }
    char pair[3] = {p[0], p[1], '\0'};
    bytes.push_back(static_cast<uint8_t>(std::strtoul(pair, nullptr, 16)));
    p += 2;
  }
  return bytes;
}

std::vector<uint8_t> Dword(uint32_t value) {
  return {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value >> 16),
          static_cast<uint8_t>(value >> 24)};
}

class Image {
 public:
  explicit Image(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}

  const std::vector<uint8_t>& bytes() const { return bytes_; }

  // Replaces bytes at a .text VA after checking that the original bytes are present.
  void Put(uint32_t va, const std::vector<uint8_t>& original, const std::vector<uint8_t>& replacement) {
    if (original.size() != replacement.size()) throw Failure(Format("0x%08X: length mismatch", va));
    size_t offset = TextOffset(va, original.size());
    if (std::memcmp(&bytes_[offset], original.data(), original.size()) != 0)
      throw Failure(Format("0x%08X: expected %s, found %s", va, HexBytes(original.data(), original.size()).c_str(),
                           HexBytes(&bytes_[offset], original.size()).c_str()));
    std::memcpy(&bytes_[offset], replacement.data(), replacement.size());
  }

  void Put(uint32_t va, const char* original, const char* replacement) {
    Put(va, ParseHex(original), ParseHex(replacement));
  }

  void PutDword(uint32_t va, uint32_t original, uint32_t replacement) { Put(va, Dword(original), Dword(replacement)); }

  // Appends the .hirest code section (file-backed) and the .zmcols uninitialized
  // read-write section (raw size 0); returns the VA of .zmcols.
  uint32_t AppendSections(const std::vector<uint8_t>& code, uint32_t bss_size) {
    if (U16(0) != 0x5A4D) throw Failure("not an MZ executable");
    uint32_t pe = U32(0x3C);
    if (U32(pe) != 0x00004550) throw Failure("not a PE executable");
    uint32_t file_header = pe + 4;
    uint32_t optional = file_header + 20;
    uint16_t count = U16(file_header + 2);
    uint16_t optional_size = U16(file_header + 16);
    uint32_t section_alignment = U32(optional + 32);
    uint32_t file_alignment = U32(optional + 36);
    uint32_t size_of_headers = U32(optional + 60);
    uint32_t table = optional + optional_size;
    uint32_t new_header = table + 40 * count;
    if (count != 5) throw Failure(Format("expected 5 sections, found %u", count));
    if (new_header + 80 > size_of_headers) throw Failure("no free section header slots");
    for (uint32_t i = 0; i < 80; ++i)
      if (bytes_[new_header + i]) throw Failure("no free section header slots");

    auto align = [](uint32_t value, uint32_t alignment) { return (value + alignment - 1) & ~(alignment - 1); };
    uint32_t last = table + 40 * (count - 1);
    uint32_t code_rva = align(U32(last + 12) + U32(last + 8), section_alignment);
    if (code_rva != U32(optional + 56)) throw Failure(Format("unexpected SizeOfImage 0x%X", U32(optional + 56)));
    if (U32(last + 20) + U32(last + 16) != bytes_.size()) throw Failure("unexpected data after the last section");
    uint32_t code_size = static_cast<uint32_t>(code.size());
    if (kImageBase + code_rva != kCodeSectionVa || code_size % file_alignment)
      throw Failure("unexpected code section placement");

    uint32_t code_pointer = static_cast<uint32_t>(bytes_.size());
    uint32_t bss_rva = code_rva + align(code_size, section_alignment);
    std::memcpy(&bytes_[new_header], kCodeSectionName, 8);
    SetU32(new_header + 8, code_size);
    SetU32(new_header + 12, code_rva);
    SetU32(new_header + 16, code_size);
    SetU32(new_header + 20, code_pointer);
    SetU32(new_header + 36, kCodeSectionCharacteristics);
    std::memcpy(&bytes_[new_header + 40], kBssSectionName, 8);
    SetU32(new_header + 48, bss_size);
    SetU32(new_header + 52, bss_rva);
    // SizeOfRawData, PointerToRawData, relocations and line numbers stay zero.
    SetU32(new_header + 76, kBssSectionCharacteristics);
    bytes_.insert(bytes_.end(), code.begin(), code.end());
    SetU16(file_header + 2, static_cast<uint16_t>(count + 2));
    SetU32(optional + 56, bss_rva + align(bss_size, section_alignment));
    SetU32(optional + 4, U32(optional + 4) + code_size);
    SetU32(optional + 12, U32(optional + 12) + align(bss_size, section_alignment));
    return kImageBase + bss_rva;
  }

 private:
  size_t TextOffset(uint32_t va, size_t length) const {
    uint32_t offset = va - kImageBase;
    if (va < kImageBase || offset < kTextRawBegin || offset + length > kTextRawEnd || offset + length > bytes_.size())
      throw Failure(Format("0x%08X: outside .text", va));
    return offset;
  }

  void Check(size_t offset, size_t length) const {
    if (offset + length > bytes_.size()) throw Failure("truncated PE header");
  }
  uint16_t U16(size_t offset) const {
    Check(offset, 2);
    return static_cast<uint16_t>(bytes_[offset] | bytes_[offset + 1] << 8);
  }
  uint32_t U32(size_t offset) const {
    Check(offset, 4);
    return bytes_[offset] | bytes_[offset + 1] << 8 | bytes_[offset + 2] << 16 | static_cast<uint32_t>(bytes_[offset + 3]) << 24;
  }
  void SetU16(size_t offset, uint16_t value) {
    Check(offset, 2);
    bytes_[offset] = static_cast<uint8_t>(value);
    bytes_[offset + 1] = static_cast<uint8_t>(value >> 8);
  }
  void SetU32(size_t offset, uint32_t value) {
    Check(offset, 4);
    for (int i = 0; i < 4; ++i) bytes_[offset + i] = static_cast<uint8_t>(value >> (8 * i));
  }

  std::vector<uint8_t> bytes_;
};

struct Layout {
  uint32_t active;
  uint32_t data;
  uint32_t guard;
};

std::vector<uint8_t> HirestImage() {
  std::vector<uint8_t> image(kCodeSectionSize, 0);
  for (const Stub& stub : kHirest) {
    std::vector<uint8_t> code = ParseHex(stub.code);
    if (stub.offset + code.size() > image.size()) throw Failure("stub outside .hirest");
    for (size_t i = 0; i < code.size(); ++i) {
      if (image[stub.offset + i]) throw Failure("overlapping .hirest stubs");
      image[stub.offset + i] = code[i];
    }
  }
  return image;
}

void Patch(Image& image) {
  const uint32_t columns = kColumns;

  // 1. Display mode and window style.
  // CWinOS::SetDisplayMode (restore paths only): ChangeDisplaySettingsA(NULL, 0); return 1.
  image.Put(0x00676CB0, "8b 01 81 ec 9c 00 00 00 ff 50 4c 66 8b 8c 24 a0 00 00",
            "6a 00 6a 00 ff 15 40 b3 7a 00 b8 01 00 00 00 c2 04 00");
  // Display_EnumAndChangeDisplaySettings16bpp: flags = test ? CDS_TEST : CDS_FULLSCREEN; 32-bit modes.
  image.Put(0x00747235, "89 74 24 10 74 08 c7 44 24 10 02 00 00 00", "f7 d8 1b c0 83 e0 fe 83 c0 04 89 44 24 10");
  image.Put(0x00747273, "10", "20");
  // Any-rate fallback: keep the mode's refresh rate; current Windows rejects the game's 0 ("default").
  image.Put(0x00747358, "75 0b", "eb 0b");
  image.Put(0x00677098, "8b 86 38 01 00 00", "b8 00 00 00 80 90");  // CreateOSWindow: dwStyle = WS_POPUP

  // 2. Stub code section and zoom-map column storage in a new BSS section.
  uint32_t active_size = 4 * columns;
  uint32_t data_size = 16 * columns;
  uint32_t base = image.AppendSections(HirestImage(), active_size + data_size + 4);
  Layout layout = {base, base + active_size, base + active_size + data_size};  // guard doubles as the data end marker

  for (uint32_t site : {0x006154F5u, 0x00615502u, 0x00615549u, 0x00615552u, 0x00615580u, 0x0079ED21u, 0x0079ED29u})
    image.PutDword(site, kOldGuard, layout.guard);
  for (uint32_t site : {0x006155ACu, 0x006157F8u}) image.PutDword(site, kOldGuard + 4, layout.guard + 4);
  for (uint32_t site : {0x0061555Fu, 0x00615797u, 0x00615860u, 0x00615873u}) image.PutDword(site, kOldActive, layout.active);
  for (uint32_t site : {0x0061551Bu, 0x0061556Eu, 0x006156A1u, 0x006156F5u, 0x007AA2FDu})
    image.PutDword(site, kOldData, layout.data);
  for (uint32_t site : {0x00615587u, 0x0061579Cu}) image.PutDword(site, kOldData + 4, layout.data + 4);

  // Element counts: vector constructor, active-array clear, atexit vector destructor.
  for (uint32_t site : {0x00615512u, 0x00615558u, 0x007AA2F6u}) image.PutDword(site, kOldColumns, columns);

  // Per-column byte array on the stack: the frame grows by the extra columns; the
  // array is the topmost local, so only the SEH-record offsets above it move.
  uint32_t extra = columns - kOldColumns;
  image.PutDword(0x006154BD, 0x860, 0x860 + extra);  // sub esp, frame
  image.PutDword(0x0061577E, 0x200, columns / 4);    // rep stosd clear of the byte array
  image.PutDword(0x00615522, 0x888, 0x888 + extra);
  image.PutDword(0x0061553B, 0x874, 0x874 + extra);
  image.PutDword(0x006158B5, 0x874, 0x874 + extra);

  // 3. Dirty-rectangle and draw-list bypasses.
  image.Put(0x00625A2D, "74 39", "90 90");                          // ExtractNextRect: always full viewport
  image.Put(0x00626CF8, "0f 84 86 00 00 00", "90 90 90 90 90 90");  // CollectLayerDrawList: unfiltered branch
  image.Put(0x00626843, "0f 84 c5 00 00 00", "e9 c6 00 00 00 90");  // UpdateViewportRegion: no scroll copy
  image.Put(0x00607E71, "74 16", "7e 16");                          // BuildScrollDeltaRegion: jz -> jle
  image.Put(0x00625DCF, "77 42", "eb 42");                          // MarkSegmentMasks: set dirty flag, skip row OR loop

  // 4. In-game resolution switching.
  // Display_ValidateAndApplyResolution stays unpatched: it lists the sizes the monitor offers as 32-bit modes.
  image.Put(0x0067851F, "f6 86 34 01 00 00 08", "e8 dc ca 41 00 90 90");  // CWinOSWindow::SetRect: call RepaintStub
  // Options keep the Settings.ini index instead of the entry matching the operating-system mode.
  image.Put(0x006E80FF, "8b 0d 40 73 a8 00", "e9 e1 00 00 00 90");
  image.Put(0x006E7E81, "74 24", "eb 24");  // ApplyScreenResolution: always apply, also the desktop size

  // 5. Windows display scaling.
  image.Put(0x0065D107, "e8 84 04 0f 00", "e8 14 7f 43 00");  // WinMain: call DpiStub before any game code
  // Desktop mode not found among the enumerated modes: ENUM_CURRENT_SETTINGS (-1) instead of mode 0.
  image.Put(0x007471FD, "33 c0", "48 90");

  // 6. Mouse confinement and edge scrolling at the game area.
  image.Put(0x0074D42E, "ff 15 c4 b2 7a 00", "e8 4d 7c 34 00 90");  // startup clip: call ClipStub
  image.Put(0x00747A9A, "8b 3d c4 b2 7a 00", "bf 80 50 a9 00 90");  // activation clip: edi = ClipStub
  image.Put(0x0067860F, "e8 5c 92 fd ff", "e8 cc ca 41 00");        // CWinOSWindow::SetRect tail: ReclipStub
  // Video_SetDisplayMode: extent = requested size, so edge-scroll zones sit at the game-area edges.
  image.Put(0x0074815A, "0f bf 44 24 10 0f bf 5c 24 0c", "8d 41 01 8b 1d 64 7c a8 00 43");
}

std::wstring FullPath(const std::wstring& path) {
  wchar_t buffer[MAX_PATH * 4];
  DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(std::size(buffer)), buffer, nullptr);
  return length && length < std::size(buffer) ? std::wstring(buffer, length) : path;
}

// Folder of the given file, with a trailing backslash.
std::wstring Folder(const std::wstring& path) {
  std::wstring full = FullPath(path);
  size_t slash = full.find_last_of(L"\\/");
  return slash == std::wstring::npos ? std::wstring() : full.substr(0, slash + 1);
}

bool Exists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }

// ---------------------------------------------------------------------------
// DATA\CONST.INI: the game reads its resolution list from [Resolutions]. The
// shipped copy inside Packs\data.pak stops at 1920x1080; a loose DATA\CONST.INI
// in the game folder takes priority over it.
// ---------------------------------------------------------------------------

// Returns one entry of an HMMSYS PackFile archive (Packs\*.pak): a 40-byte header
// with the entry count at +0x20, then a front-coded directory of (name length,
// length shared with the previous name, name suffix, u32 offset, u32 size).
// The entries of data.pak are stored uncompressed.
std::vector<uint8_t> ReadPakEntry(const std::wstring& pak_path, const char* wanted) {
  std::vector<uint8_t> data = ReadFile(pak_path);
  static const char kMagic[] = "HMMSYS PackFile";
  if (data.size() < 0x28 || std::memcmp(data.data(), kMagic, sizeof kMagic - 1) != 0)
    throw Failure(Narrow(pak_path) + " is not an HMMSYS PackFile archive");
  auto u32 = [&data](size_t offset) {
    return data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16 | static_cast<uint32_t>(data[offset + 3]) << 24;
  };
  uint32_t count = u32(0x20);
  size_t position = 0x28;
  std::string name;
  for (uint32_t i = 0; i < count; ++i) {
    if (position + 2 > data.size()) throw Failure("truncated pak directory");
    size_t total = data[position];
    size_t prefix = data[position + 1];
    if (prefix > total || prefix > name.size() || position + 2 + (total - prefix) + 8 > data.size())
      throw Failure("corrupt pak directory");
    name = name.substr(0, prefix) + std::string(reinterpret_cast<const char*>(&data[position + 2]), total - prefix);
    position += 2 + total - prefix;
    uint32_t offset = u32(position);
    uint32_t size = u32(position + 4);
    position += 8;
    if (_stricmp(name.c_str(), wanted) != 0) continue;
    if (static_cast<uint64_t>(offset) + size > data.size()) throw Failure("pak entry outside the archive");
    return std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + size);
  }
  throw Failure(std::string(wanted) + " not found in " + Narrow(pak_path));
}

std::string Trim(const std::string& text) {
  size_t begin = text.find_first_not_of(" \t");
  if (begin == std::string::npos) return "";
  return text.substr(begin, text.find_last_not_of(" \t") - begin + 1);
}

// Returns N for a "Res<N>_x" or "Res<N>_y" key (axis in *axis), otherwise 0.
int ResolutionKey(const std::string& key, char* axis) {
  size_t underscore = key.find('_');
  if (key.size() < 6 || _strnicmp(key.c_str(), "Res", 3) != 0 || underscore == std::string::npos ||
      underscore <= 3 || underscore + 2 != key.size())
    return 0;
  std::string digits = key.substr(3, underscore - 3);
  if (digits.find_first_not_of("0123456789") != std::string::npos) return 0;
  *axis = static_cast<char>(std::tolower(static_cast<unsigned char>(key.back())));
  return *axis == 'x' || *axis == 'y' ? std::atoi(digits.c_str()) : 0;
}

// Lists width x height first in [Resolutions] and renumbers the other entries.
// Returns false, leaving *ini unchanged, when the size is already listed.
bool ListResolutionFirst(std::string* ini, int width, int height) {
  const std::string eol = ini->find("\r\n") != std::string::npos ? "\r\n" : "\n";
  std::vector<std::string> lines;
  for (size_t start = 0; start < ini->size();) {
    size_t end = std::min(ini->find('\n', start), ini->size());
    std::string line = ini->substr(start, end - start);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    lines.push_back(line);
    start = end + 1;
  }

  size_t header = 0;
  while (header < lines.size() && _stricmp(Trim(lines[header]).c_str(), "[Resolutions]") != 0) ++header;
  if (header == lines.size()) throw Failure("CONST.INI has no [Resolutions] section");
  size_t end = header + 1;
  while (end < lines.size() && Trim(lines[end]).compare(0, 1, "[") != 0) ++end;

  std::map<int, std::pair<int, int>> sizes;
  std::vector<std::string> others;  // comments and blank lines, kept after the entries
  for (size_t i = header + 1; i < end; ++i) {
    size_t equals = lines[i].find('=');
    char axis = 0;
    int index = equals == std::string::npos ? 0 : ResolutionKey(Trim(lines[i].substr(0, equals)), &axis);
    if (index <= 0) {
      others.push_back(lines[i]);
      continue;
    }
    int value = std::atoi(Trim(lines[i].substr(equals + 1)).c_str());
    (axis == 'x' ? sizes[index].first : sizes[index].second) = value;
  }

  std::vector<std::string> block = {Format("Res1_x=%d", width), Format("Res1_y=%d", height)};
  int next = 2;
  for (const auto& entry : sizes) {
    if (entry.second == std::make_pair(width, height)) return false;
    if (entry.second.first <= 0 || entry.second.second <= 0) continue;
    block.push_back(Format("Res%d_x=%d", next, entry.second.first));
    block.push_back(Format("Res%d_y=%d", next++, entry.second.second));
  }
  block.insert(block.end(), others.begin(), others.end());
  lines.erase(lines.begin() + header + 1, lines.begin() + end);
  lines.insert(lines.begin() + header + 1, block.begin(), block.end());
  ini->clear();
  for (const std::string& line : lines) *ini += line + eol;
  return true;
}

// Writes DATA\CONST.INI with 2560x1440 listed first, starting from the loose
// file when there is one (kept as CONST.INI.bak) or from Packs\data.pak.
void InstallConstIni(const std::wstring& game_dir) {
  const std::wstring data_dir = game_dir + L"DATA";
  const std::wstring loose = data_dir + L"\\CONST.INI";
  const std::wstring pak = game_dir + L"Packs\\data.pak";
  const bool had_loose = Exists(loose);
  std::vector<uint8_t> original;
  if (had_loose) {
    original = ReadFile(loose);
  } else if (Exists(pak)) {
    original = ReadPakEntry(pak, "DATA\\CONST.INI");
  } else {
    std::wprintf(L"[WARN] DATA\\CONST.INI was not written: neither it nor Packs\\data.pak is next to the source.\n"
                 L"       Patch the gbr.exe inside the game folder so the game lists %dx%d.\n", kWidth, kHeight);
    return;
  }
  if (original.size() >= 4 && std::memcmp(original.data(), "LZIS", 4) == 0)
    throw Failure("CONST.INI is LZIS-compressed; only the uncompressed file is supported");

  std::string ini(original.begin(), original.end());
  if (!ListResolutionFirst(&ini, kWidth, kHeight)) {
    std::wprintf(L"[OK] %hs already lists %dx%d\n", Narrow(loose).c_str(), kWidth, kHeight);
    return;
  }
  if (had_loose) {
    const std::wstring backup = loose + L".bak";
    if (!Exists(backup) && !CopyFileW(loose.c_str(), backup.c_str(), TRUE))
      throw Failure("cannot back up " + Narrow(loose));
  } else if (!CreateDirectoryW(data_dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
    throw Failure("cannot create " + Narrow(data_dir));
  }
  WriteFile(loose, std::vector<uint8_t>(ini.begin(), ini.end()));
  std::wprintf(L"[OK] %hs: %dx%d listed first (%hs)\n", Narrow(loose).c_str(), kWidth, kHeight,
               had_loose ? "previous file kept as CONST.INI.bak" : "from Packs\\data.pak");
}

void PrintUsage() {
  std::wprintf(
      L"Native 1440p patcher for Imperivm III HD gbr.exe, revision r7\n\n"
      L"  1440p_patch.exe <gbr.exe> [output.exe] [--force]\n"
      L"  1440p_patch.exe --identify <exe>\n\n"
      L"  <gbr.exe>     vanilla official HD executable (SHA-256 72b09d1a...) in the game folder\n"
      L"  [output.exe]  default: %ls next to the source; never the source itself\n"
      L"  --force       overwrite an existing output file\n"
      L"  --identify    report whether an executable is a known vanilla or patched build\n",
      kDefaultOutputName);
}

void PrintSetupNotes() {
  std::wprintf(
      L"\nNext steps:\n"
      L"  1. Back up gbr.exe, then replace it with %ls (renamed to gbr.exe).\n"
      L"  2. Choose 2560 x 1440 in the game's Options. The list only shows sizes your monitor\n"
      L"     supports; Settings.ini [Options] Resolution= is the zero-based index in that list.\n"
      L"  The game switches the monitor to the chosen size and restores the desktop mode when it\n"
      L"  exits (not when it is ended from Task Manager). Windows display scaling needs no setting:\n"
      L"  the game is DPI aware by itself.\n",
      kDefaultOutputName);
}

int Identify(const std::wstring& path) {
  std::string sha256 = Sha256Hex(ReadFile(path));
  const char* description = DescribeBuild(sha256);
  std::wprintf(L"%hs\n  sha256 %hs\n  %hs\n", Narrow(path).c_str(), sha256.c_str(),
               description ? description : "unknown build");
  return description ? 0 : 2;
}

int Run(int argc, wchar_t** argv) {
  std::vector<std::wstring> positional;
  bool force = false;
  bool identify = false;
  for (int i = 1; i < argc; ++i) {
    std::wstring arg = argv[i];
    if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
      PrintUsage();
      return 0;
    } else if (arg == L"--force") {
      force = true;
    } else if (arg == L"--identify") {
      identify = true;
    } else if (arg.size() > 1 && arg[0] == L'-' && arg[1] == L'-') {
      throw Failure("unknown option " + Narrow(arg));
    } else {
      positional.push_back(arg);
    }
  }

  if (identify) {
    if (positional.size() != 1) throw Failure("--identify takes exactly one executable");
    return Identify(positional[0]);
  }
  if (positional.empty() || positional.size() > 2) {
    PrintUsage();
    return 1;
  }
  const std::wstring source = positional[0];
  const std::wstring output = positional.size() == 2 ? positional[1] : Folder(source) + kDefaultOutputName;
  if (_wcsicmp(FullPath(source).c_str(), FullPath(output).c_str()) == 0) throw Failure("refusing to overwrite the source");
  if (Exists(output) && !force) throw Failure(Narrow(output) + " already exists (use --force to overwrite)");

  std::vector<uint8_t> data = ReadFile(source);
  std::string source_sha256 = Sha256Hex(data);
  if (source_sha256 != kVanillaSha256) {
    const char* description = DescribeBuild(source_sha256);
    throw Failure("source is not the vanilla HD gbr.exe (sha256 " + source_sha256 + ", " +
                  (description ? description : "unknown build") + ")");
  }

  Image image(std::move(data));
  Patch(image);
  std::string output_sha256 = Sha256Hex(image.bytes());
  if (output_sha256 != kPatchedSha256) throw Failure("output does not match the reference build (" + output_sha256 + ")");

  WriteFile(output, image.bytes());
  std::wprintf(L"[OK] %hs\n", Narrow(FullPath(output)).c_str());
  std::wprintf(L"     revision r7, sha256 %hs (matches the reference build)\n", output_sha256.c_str());
  InstallConstIni(Folder(source));
  PrintSetupNotes();
  return 0;
}

// Keeps the window open when the patcher owns its console (double click or drag and drop).
void PauseIfOwnConsole() {
  DWORD processes[2];
  if (GetConsoleProcessList(processes, 2) == 1) {
    std::wprintf(L"\nPress Enter to close.");
    std::fflush(stdout);
    std::getwchar();
  }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::setlocale(LC_ALL, "");
  int status;
  try {
    status = Run(argc, argv);
  } catch (const std::exception& error) {
    std::wprintf(L"[ERROR] %hs\n", error.what());
    status = 1;
  }
  PauseIfOwnConsole();
  return status;
}
