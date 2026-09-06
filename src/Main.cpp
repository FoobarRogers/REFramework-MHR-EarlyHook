#include <chrono>
#include <mutex>
#include <thread>
#include <windows.h>
#include <winternl.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include <MinHook.h>

#include <utility/Module.hpp>
#include <utility/Thread.hpp>

#include <sdk/GameIdentity.hpp>
#include <safetyhook/allocator.hpp>

// minhook, used for AllocateBuffer
extern "C" {
#include <../buffer.h>
};

#include "mods/IntegrityCheckBypass.hpp"
#include "ExceptionHandler.hpp"
#include "REFramework.hpp"

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

    // Use a dedicated log because this runs before REFramework's normal logger exists.
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

HMODULE g_dinput = 0;
decltype(DirectInput8Create)* g_original_dinput8_create = nullptr;
std::mutex g_load_mutex{};
extern bool g_success_made_ldr_notification;

void failed() {
    MessageBox(0, "REFramework: Unable to load the original dinput8.dll. Please report this to the developer.", "REFramework", 0);
    ExitProcess(0);
}

bool load_dinput8() {
    std::scoped_lock _{g_load_mutex};

    if (g_dinput) {
        return true;
    }

    wchar_t buffer[MAX_PATH]{0};
    if (GetSystemDirectoryW(buffer, MAX_PATH) != 0) {
        // Load the original dinput8.dll
        if ((g_dinput = LoadLibraryW((std::wstring{buffer} + L"\\dinput8.dll").c_str())) == NULL) {
            failed();
            return false;
        }

        // Cache the original proc address immediately before any overlay (e.g. EOS) can hook it
        g_original_dinput8_create = (decltype(DirectInput8Create)*)GetProcAddress(g_dinput, "DirectInput8Create");

        return true;
    }

    failed();
    return false;
}

extern "C" {
// DirectInput8Create wrapper for dinput8.dll
__declspec(dllexport) HRESULT WINAPI
    direct_input8_create(HINSTANCE hinst, DWORD dw_version, const IID& riidltf, LPVOID* ppv_out, LPUNKNOWN punk_outer) {
// This needs to be done because when we include dinput.h in DInputHook,
// It is a redefinition, so we assign an export by not using the original name
#pragma comment(linker, "/EXPORT:DirectInput8Create=direct_input8_create")

    // Reentrancy guard: overlays like EOS hook DirectInput8Create in the system DLL,
    // and their hook calls back into our export, causing infinite recursion / stack overflow.
    // On re-entry, call the real system function directly so the chain still completes.
    static thread_local bool s_in_call = false;

    load_dinput8();

    if (s_in_call) {
        return g_original_dinput8_create(hinst, dw_version, riidltf, ppv_out, punk_outer);
    }

    s_in_call = true;
    auto result = g_original_dinput8_create(hinst, dw_version, riidltf, ppv_out, punk_outer);
    s_in_call = false;
    return result;
}
}

void startup_thread(HMODULE reframework_module) {
    // Test7: run the MH Rise resource probe before exception setup, system dinput8
    // loading, REFramework construction, mod initialization, Lua, or PluginLoader.
    // The probe is diagnostic only and never changes game return values.
    mhr_early_hook_probe::initialize();

    // We will set it once here, then do it continuously
    // every now and then because it gets replaced
    reframework::setup_exception_handler();

#ifndef NDEBUG
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
#endif

    // GameIdentity::initialize() already called from DllMain (before integrity hooks).
    // The call is idempotent, but the authoritative init is the DllMain one.

    if (load_dinput8()) {
        g_framework = std::make_unique<REFramework>(reframework_module);

        const auto our_dll = utility::get_module_within(&load_dinput8);
        const auto& gi = sdk::GameIdentity::get();

        if (gi.is_mhrise()) {
            if (our_dll) {
                if (!g_success_made_ldr_notification) {
                    utility::spoof_module_paths_in_exe_dir();
                }
                utility::unlink(*our_dll);
            }
        } else if (gi.is_dd2() || gi.tdb_ver() >= 74) {
            if (!g_success_made_ldr_notification) {
                utility::spoof_module_paths_in_exe_dir();
            }
        }
    }
}

BOOL APIENTRY DllMain(HANDLE handle, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        REFramework::set_reframework_module((HMODULE)handle);
        mhr_early_hook_probe::set_attach_tick(GetTickCount64());

        const auto game = utility::get_executable();
        const auto module_size = utility::get_module_size(game).value_or(0);
        const auto halfway_module = (uintptr_t)game + (module_size / 2);

        // Need to pin the safetyhook allocator because it destroys itself
        static auto sh_allocator = safetyhook::Allocator::global();
        // 1MB
        intptr_t requested_size = 1 * 1024 * 1024;
        // Keep attempting to allocate and reduce requested size by 1 page until successful
        // 1MB is just the higher end of the range, it will allocate less if it can
        // even 10kb would be enough for a decent amount of hooks, but we want as much as we can near the middle
        while (requested_size > 0 && !sh_allocator->allocate_near({(uint8_t*)halfway_module}, requested_size)) {
            requested_size -= 0x1000; // Size of page
        }

        AllocateBuffer((LPVOID)halfway_module); // minhook

        // GameIdentity must be initialized before the integrity hooks below,
        // because hook_add_vectored_exception_handler gates on tdb_ver() >= 73.
        // Safe under loader lock: detection is just GetModuleFileNameW.
        sdk::GameIdentity::initialize();

        IntegrityCheckBypass::setup_pristine_syscall();
        IntegrityCheckBypass::hook_add_vectored_exception_handler();
        IntegrityCheckBypass::hook_rtl_exit_user_process();

        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)startup_thread, handle, 0, nullptr);
    }

    return TRUE;
}
