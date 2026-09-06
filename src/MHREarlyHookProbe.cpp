#include "MHREarlyHookProbe.hpp"

#include <Windows.h>
#include <MinHook.h>

#include <sdk/GameIdentity.hpp>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace mhr_early_hook_probe {
namespace {

constexpr std::uint64_t kVoiceHashNonStreaming = 0x2DF225C5E2B3D254ULL;
constexpr std::uint64_t kVoiceHashStreaming = 0xB8760B4CE9D1EC2DULL;
constexpr std::size_t kMaxVoicePathLogs = 256;

using PathToHashFn = std::uint64_t (*)(wchar_t*);
using CheckFileInPakFn = int (*)(void*, std::uint64_t);

PathToHashFn g_path_to_hash_original{};
CheckFileInPakFn g_check_file_in_pak_original{};

std::atomic<std::uint64_t> g_attach_tick{0};
std::atomic<bool> g_initialized{false};
std::atomic<std::size_t> g_voice_path_log_count{0};
std::mutex g_log_mutex{};

struct Pattern {
    const std::uint8_t* bytes{};
    std::size_t size{};
};

constexpr std::uint8_t kPathToHashPattern[] = {
    0x40, 0x55, 0x53, 0x41, 0x56, 0x48, 0x8D, 0xAC, 0x24, 0xC0, 0xF0, 0xFF, 0xFF
};

constexpr std::uint8_t kCheckFileInPakPattern1[] = {
    0x48, 0x89, 0x6C, 0x24, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20,
    0x48, 0x83, 0xB9, 0xA8, 0x00, 0x00, 0x00, 0x00
};

constexpr std::uint8_t kCheckFileInPakPattern2[] = {
    0x48, 0x89, 0x6C, 0x24, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x45, 0x33, 0xC0
};

std::wstring log_path() {
    std::wstring buffer(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return L"mhr_earlyhook_test7.log";
    }

    buffer.resize(length);
    const auto slash = buffer.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        buffer.resize(slash + 1);
    } else {
        buffer.clear();
    }

    buffer += L"mhr_earlyhook_test7.log";
    return buffer;
}

void write_log(const char* fmt, ...) {
    char message[3072]{};
    va_list args{};
    va_start(args, fmt);
    vsnprintf_s(message, sizeof(message), _TRUNCATE, fmt, args);
    va_end(args);

    const auto now = GetTickCount64();
    const auto attach = g_attach_tick.load(std::memory_order_acquire);
    const auto delta = now >= attach ? now - attach : 0;

    char line[3584]{};
    snprintf(line, sizeof(line), "[MHR EarlyHook Test7 +%llums] %s\r\n",
             static_cast<unsigned long long>(delta), message);

    OutputDebugStringA(line);

    std::lock_guard lock{g_log_mutex};
    const auto path = log_path();
    const HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written{};
    WriteFile(file, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
    CloseHandle(file);
}

bool is_target_voice_hash(std::uint64_t hash) {
    return hash == kVoiceHashNonStreaming || hash == kVoiceHashStreaming;
}

bool is_player_voice_path(const wchar_t* path) {
    return path != nullptr && wcsstr(path, L"pl_voice_") != nullptr;
}

struct ScanRange {
    std::uint8_t* begin{};
    std::size_t size{};
};

std::vector<ScanRange> executable_ranges() {
    std::vector<ScanRange> ranges{};
    auto* module = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
    if (module == nullptr) {
        return ranges;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return ranges;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return ranges;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }

        const auto mapped_size = section[i].Misc.VirtualSize != 0
            ? section[i].Misc.VirtualSize
            : section[i].SizeOfRawData;
        if (mapped_size == 0) {
            continue;
        }

        ranges.push_back({module + section[i].VirtualAddress, static_cast<std::size_t>(mapped_size)});
    }

    return ranges;
}

std::vector<std::uint8_t*> scan_all(Pattern pattern) {
    std::vector<std::uint8_t*> matches{};
    if (pattern.bytes == nullptr || pattern.size == 0) {
        return matches;
    }

    for (const auto& range : executable_ranges()) {
        if (range.size < pattern.size) {
            continue;
        }

        for (std::size_t i = 0; i <= range.size - pattern.size; ++i) {
            if (memcmp(range.begin + i, pattern.bytes, pattern.size) == 0) {
                matches.push_back(range.begin + i);
            }
        }
    }

    return matches;
}

void* scan_unique(const char* label, Pattern primary, Pattern fallback = {}) {
    auto matches = scan_all(primary);
    if (matches.size() == 1) {
        write_log("%s found at %p", label, matches.front());
        return matches.front();
    }

    write_log("%s primary pattern matched %zu location(s)", label, matches.size());

    if (fallback.bytes != nullptr && fallback.size != 0) {
        matches = scan_all(fallback);
        if (matches.size() == 1) {
            write_log("%s fallback found at %p", label, matches.front());
            return matches.front();
        }
        write_log("%s fallback pattern matched %zu location(s)", label, matches.size());
    }

    return nullptr;
}

std::uint64_t path_to_hash_hook(wchar_t* path) {
    const auto hash = g_path_to_hash_original(path);

    if (is_player_voice_path(path)) {
        const auto index = g_voice_path_log_count.fetch_add(1, std::memory_order_relaxed);
        if (index < kMaxVoicePathLogs) {
            write_log("EARLY PathToHash player voice #%zu: hash=0x%016llX path=%ls",
                      index + 1,
                      static_cast<unsigned long long>(hash),
                      path != nullptr ? path : L"<null>");
        }
    } else if (is_target_voice_hash(hash)) {
        write_log("EARLY PathToHash TARGET HASH: hash=0x%016llX path=%ls",
                  static_cast<unsigned long long>(hash),
                  path != nullptr ? path : L"<null>");
    }

    return hash;
}

int check_file_in_pak_hook(void* context, std::uint64_t hash) {
    const int result = g_check_file_in_pak_original(context, hash);

    if (is_target_voice_hash(hash)) {
        write_log("EARLY CheckFileInPak TARGET: context=%p hash=0x%016llX original=%d",
                  context,
                  static_cast<unsigned long long>(hash),
                  result);
    }

    return result;
}

bool install_hook(void* target, void* detour, void** original, const char* label) {
    if (target == nullptr) {
        write_log("%s hook skipped: target is null", label);
        return false;
    }

    const auto create_status = MH_CreateHook(target, detour, original);
    if (create_status != MH_OK) {
        write_log("MH_CreateHook(%s) failed: %d", label, static_cast<int>(create_status));
        return false;
    }

    const auto enable_status = MH_EnableHook(target);
    if (enable_status != MH_OK) {
        write_log("MH_EnableHook(%s) failed: %d", label, static_cast<int>(enable_status));
        return false;
    }

    write_log("%s hook enabled at %p", label, target);
    return true;
}

} // namespace

void set_attach_tick(std::uint64_t tick) {
    g_attach_tick.store(tick, std::memory_order_release);
}

void initialize() {
    if (g_initialized.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    const auto& game = sdk::GameIdentity::get();
    if (!game.is_mhrise()) {
        return;
    }

    // Create a fresh diagnostic file for each launch. This is intentionally
    // independent of REFramework's logger because the probe runs before the
    // normal REFramework object and logging pipeline are initialized.
    {
        std::lock_guard lock{g_log_mutex};
        const auto path = log_path();
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
    }

    write_log("Starting Test7 probe at the first startup_thread instruction before REFramework construction.");
    write_log("Diagnostic only: hook return values are never modified.");
    write_log("Targets: nonstream=0x%016llX streaming=0x%016llX",
              static_cast<unsigned long long>(kVoiceHashNonStreaming),
              static_cast<unsigned long long>(kVoiceHashStreaming));

    auto* path_to_hash = scan_unique(
        "PathToHash",
        {kPathToHashPattern, sizeof(kPathToHashPattern)}
    );

    auto* check_file_in_pak = scan_unique(
        "CheckFileInPak",
        {kCheckFileInPakPattern1, sizeof(kCheckFileInPakPattern1)},
        {kCheckFileInPakPattern2, sizeof(kCheckFileInPakPattern2)}
    );

    const auto init_status = MH_Initialize();
    if (init_status != MH_OK && init_status != MH_ERROR_ALREADY_INITIALIZED) {
        write_log("MH_Initialize failed: %d", static_cast<int>(init_status));
        return;
    }

    const bool path_ok = install_hook(path_to_hash,
                                      reinterpret_cast<void*>(&path_to_hash_hook),
                                      reinterpret_cast<void**>(&g_path_to_hash_original),
                                      "PathToHash");

    const bool pak_ok = install_hook(check_file_in_pak,
                                     reinterpret_cast<void*>(&check_file_in_pak_hook),
                                     reinterpret_cast<void**>(&g_check_file_in_pak_original),
                                     "CheckFileInPak");

    write_log("Test7 probe installation complete: PathToHash=%s CheckFileInPak=%s",
              path_ok ? "OK" : "FAILED",
              pak_ok ? "OK" : "FAILED");
}

} // namespace mhr_early_hook_probe
