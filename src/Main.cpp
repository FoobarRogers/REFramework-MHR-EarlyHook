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
#include <string>

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

// Exact RVAs observed in Test8 on this MHR executable build.
// Test8 found both signatures during poll #7 before attempting any hook:
//   PathToHash      VA 00007FF7E74C82A0 with module base 00007FF7E3250000
//   CheckFileInPak  VA 00007FF7E74C72B0 with module base 00007FF7E3250000
constexpr std::uintptr_t kPathToHashRva = 0x042782A0;
constexpr std::uintptr_t kCheckFileInPakRva = 0x042772B0;

constexpr std::uint64_t kObserveDurationMs = 20000;
constexpr DWORD kPollSleepMs = 1;
constexpr std::uint64_t kPreAppearanceReportMs = 500;
constexpr std::uint64_t kStableReportMs = 1000;

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

std::atomic<std::uint64_t> g_attach_tick{0};
std::atomic<bool> g_initialized{false};
std::mutex g_log_mutex{};

std::wstring log_path() {
    std::wstring buffer(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return L"mhr_earlyhook_test8b.log";
    }

    buffer.resize(length);
    const auto slash = buffer.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        buffer.resize(slash + 1);
    } else {
        buffer.clear();
    }

    buffer += L"mhr_earlyhook_test8b.log";
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
    snprintf(line, sizeof(line), "[MHR EarlyHook Test8b +%llums] %s\r\n",
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

bool bytes_match(const std::uint8_t* address, const std::uint8_t* pattern, std::size_t pattern_size) {
    return address != nullptr && memcmp(address, pattern, pattern_size) == 0;
}

const char* pak_variant(const std::uint8_t* address) {
    if (bytes_match(address, kCheckFileInPakPattern1, sizeof(kCheckFileInPakPattern1))) {
        return "primary";
    }
    if (bytes_match(address, kCheckFileInPakPattern2, sizeof(kCheckFileInPakPattern2))) {
        return "fallback";
    }
    return "absent";
}

void log_bytes(const char* label, const std::uint8_t* address, std::size_t count = 16) {
    char bytes[16 * 3 + 1]{};
    const auto capped = count > 16 ? 16 : count;
    std::size_t cursor{};

    for (std::size_t i = 0; i < capped && cursor + 3 < sizeof(bytes); ++i) {
        const auto written = snprintf(bytes + cursor, sizeof(bytes) - cursor,
                                      i + 1 == capped ? "%02X" : "%02X ", address[i]);
        if (written <= 0) {
            break;
        }
        cursor += static_cast<std::size_t>(written);
    }

    write_log("%s bytes @ %p: %s", label, address, bytes);
}

void poll_worker() {
    auto* module = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
    if (module == nullptr) {
        write_log("Test8b aborted: MonsterHunterRise.exe module handle is null");
        return;
    }

    auto* path_address = module + kPathToHashRva;
    auto* pak_address = module + kCheckFileInPakRva;

    write_log("Test8b scan-only worker started. NO MinHook calls and NO writes to MonsterHunterRise.exe are performed.");
    write_log("Known RVAs from Test8: PathToHash=0x%llX CheckFileInPak=0x%llX",
              static_cast<unsigned long long>(kPathToHashRva),
              static_cast<unsigned long long>(kCheckFileInPakRva));
    write_log("Resolved addresses: PathToHash=%p CheckFileInPak=%p", path_address, pak_address);
    write_log("Polling the two exact addresses every nominal %lu ms for %llums.",
              static_cast<unsigned long>(kPollSleepMs),
              static_cast<unsigned long long>(kObserveDurationMs));

    log_bytes("Initial PathToHash", path_address);
    log_bytes("Initial CheckFileInPak", pak_address);

    bool path_previous = bytes_match(path_address, kPathToHashPattern, sizeof(kPathToHashPattern));
    const char* pak_previous_variant = pak_variant(pak_address);
    bool pak_previous = strcmp(pak_previous_variant, "absent") != 0;

    bool path_ever = path_previous;
    bool pak_ever = pak_previous;
    std::uint64_t path_first_delta = 0;
    std::uint64_t pak_first_delta = 0;

    const auto attach = g_attach_tick.load(std::memory_order_acquire);
    const auto initial_now = GetTickCount64();
    const auto initial_delta = initial_now >= attach ? initial_now - attach : 0;

    if (path_previous) {
        path_first_delta = initial_delta;
        write_log("PathToHash already matches at worker start (+%llums)",
                  static_cast<unsigned long long>(path_first_delta));
    }
    if (pak_previous) {
        pak_first_delta = initial_delta;
        write_log("CheckFileInPak already matches (%s) at worker start (+%llums)",
                  pak_previous_variant,
                  static_cast<unsigned long long>(pak_first_delta));
    }

    const auto worker_start = GetTickCount64();
    std::uint64_t next_preappearance_report = kPreAppearanceReportMs;
    std::uint64_t next_stable_report = kStableReportMs;
    std::size_t polls = 0;

    while (GetTickCount64() - worker_start < kObserveDurationMs) {
        ++polls;

        const bool path_now = bytes_match(path_address, kPathToHashPattern, sizeof(kPathToHashPattern));
        const char* pak_now_variant = pak_variant(pak_address);
        const bool pak_now = strcmp(pak_now_variant, "absent") != 0;

        const auto now = GetTickCount64();
        const auto delta = now >= attach ? now - attach : 0;
        const auto worker_elapsed = now - worker_start;

        if (path_now != path_previous) {
            if (path_now) {
                if (!path_ever) {
                    path_ever = true;
                    path_first_delta = delta;
                    write_log("PathToHash FIRST APPEARED at +%llums after %zu direct polls",
                              static_cast<unsigned long long>(delta), polls);
                } else {
                    write_log("PathToHash REAPPEARED at +%llums",
                              static_cast<unsigned long long>(delta));
                }
                log_bytes("PathToHash matched", path_address);
            } else {
                write_log("PathToHash DISAPPEARED/CHANGED at +%llums",
                          static_cast<unsigned long long>(delta));
                log_bytes("PathToHash changed", path_address);
            }
            path_previous = path_now;
        }

        if (pak_now != pak_previous || (pak_now && strcmp(pak_now_variant, pak_previous_variant) != 0)) {
            if (pak_now) {
                if (!pak_ever) {
                    pak_ever = true;
                    pak_first_delta = delta;
                    write_log("CheckFileInPak FIRST APPEARED (%s) at +%llums after %zu direct polls",
                              pak_now_variant,
                              static_cast<unsigned long long>(delta), polls);
                } else if (!pak_previous) {
                    write_log("CheckFileInPak REAPPEARED (%s) at +%llums",
                              pak_now_variant,
                              static_cast<unsigned long long>(delta));
                } else {
                    write_log("CheckFileInPak signature variant changed %s -> %s at +%llums",
                              pak_previous_variant,
                              pak_now_variant,
                              static_cast<unsigned long long>(delta));
                }
                log_bytes("CheckFileInPak matched", pak_address);
            } else {
                write_log("CheckFileInPak DISAPPEARED/CHANGED at +%llums",
                          static_cast<unsigned long long>(delta));
                log_bytes("CheckFileInPak changed", pak_address);
            }
            pak_previous = pak_now;
            pak_previous_variant = pak_now_variant;
        }

        if ((!path_ever || !pak_ever) && worker_elapsed >= next_preappearance_report) {
            write_log("Awaiting signatures: elapsed=%llums PathToHash=%s CheckFileInPak=%s",
                      static_cast<unsigned long long>(worker_elapsed),
                      path_now ? "MATCH" : "absent",
                      pak_now ? pak_now_variant : "absent");
            next_preappearance_report += kPreAppearanceReportMs;
        }

        if (path_ever && pak_ever && worker_elapsed >= next_stable_report) {
            write_log("Stability checkpoint: elapsed=%llums PathToHash=%s CheckFileInPak=%s",
                      static_cast<unsigned long long>(worker_elapsed),
                      path_now ? "MATCH" : "changed",
                      pak_now ? pak_now_variant : "changed");
            next_stable_report += kStableReportMs;
        }

        Sleep(kPollSleepMs);
    }

    const bool path_final = bytes_match(path_address, kPathToHashPattern, sizeof(kPathToHashPattern));
    const char* pak_final_variant = pak_variant(pak_address);
    const bool pak_final = strcmp(pak_final_variant, "absent") != 0;

    write_log("Test8b observation finished after %zu polls: PathToHash first=%s%llums final=%s; CheckFileInPak first=%s%llums final=%s",
              polls,
              path_ever ? "+" : "never/",
              static_cast<unsigned long long>(path_first_delta),
              path_final ? "MATCH" : "changed",
              pak_ever ? "+" : "never/",
              static_cast<unsigned long long>(pak_first_delta),
              pak_final ? pak_final_variant : "changed");
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

    write_log("Starting Test8b scan-only probe at the first startup_thread instruction before REFramework construction.");
    write_log("This build observes only the exact code bytes discovered by Test8; it does not install PathToHash/CheckFileInPak hooks.");

    std::thread{poll_worker}.detach();
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
    // Test8b: start a scan-only MHR timing probe before REFramework construction.
    // It performs memory reads only and never writes or hooks the target functions.
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
