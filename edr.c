#include <windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <wchar.h>
#include <wctype.h>
#include <stdio.h>
#include <string.h>
#include "edr.h"

volatile LONG X01Stop = 0;

static BCRYPT_ALG_HANDLE X01Alg;
static WCHAR X01WinDir[MAX_PATH];
static size_t X01WinDirLen;

static const WCHAR *X01Tools[] = {
    L"mimikatz.exe", L"rubeus.exe", L"lazagne.exe", L"psexec.exe",
    L"psexesvc.exe", L"procdump.exe", L"procdump64.exe", L"nc.exe", L"ncat.exe"
};

static const WCHAR *X01Lolbins[] = {
    L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe", L"mshta.exe",
    L"rundll32.exe", L"regsvr32.exe", L"certutil.exe", L"bitsadmin.exe",
    L"wmic.exe", L"cmd.exe", L"msbuild.exe", L"installutil.exe"
};

static const WCHAR *X01OfficeApps[] = {
    L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
    L"msaccess.exe", L"onenote.exe", L"acrord32.exe", L"mspub.exe"
};

static const WCHAR *X01SystemNames[] = {
    L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe",
    L"winlogon.exe", L"smss.exe", L"wininit.exe", L"explorer.exe", L"taskhostw.exe"
};

static const WCHAR *X01UserPaths[] = {
    L"\\appdata\\local\\temp\\", L"\\windows\\temp\\", L"\\users\\public\\",
    L"\\downloads\\", L"\\$recycle.bin\\", L"\\perflogs\\"
};

static const WCHAR *X01CmdHigh[] = {
    L"vssadmin delete shadows", L"shadowcopy delete", L"wbadmin delete catalog",
    L"recoveryenabled no", L"sekurlsa::", L"lsass.dmp", L"comsvcs.dll, minidump",
    L"comsvcs.dll minidump"
};

static const WCHAR *X01CmdMedium[] = {
    L" -enc ", L" -encodedcommand", L" -e jab", L"frombase64string", L"downloadstring",
    L"downloadfile", L"invoke-expression", L"iex(", L"iex (", L"-w hidden",
    L"-windowstyle hidden", L"-exec bypass", L"-executionpolicy bypass",
    L"-urlcache", L"/transfer", L"javascript:", L"scrobj.dll"
};

static const WCHAR *X01ScriptExt[] = {
    L".ps1", L".psm1", L".vbs", L".vbe", L".js", L".jse", L".wsf", L".hta",
    L".bat", L".cmd"
};

static const WCHAR *X01PeExt[] = {
    L".exe", L".dll", L".scr", L".sys", L".com", L".cpl", L".msi"
};

static const WCHAR *X01DocExt[] = {
    L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".txt",
    L".jpg", L".png", L".zip", L".rtf"
};

static const WCHAR *X01Keywords[] = {
    L"mimikatz", L"payload", L"shellcode", L"rubeus", L"lazagne"
};

BOOL X01EdrInit(void) {
    UINT n = GetWindowsDirectoryW(X01WinDir, MAX_PATH - 1);
    size_t i;

    for (i = 0; i < n; ++i) {
        X01WinDir[i] = (WCHAR)towlower(X01WinDir[i]);
    }
    X01WinDir[n] = L'\\';
    X01WinDir[n + 1] = 0;
    X01WinDirLen = n + 1;

    return BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&X01Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0));
}

void X01EdrClose(void) {
    if (X01Alg) {
        BCryptCloseAlgorithmProvider(X01Alg, 0);
        X01Alg = NULL;
    }
}

const char *X01RiskName(RiskLevel level) {
    static const char *names[] = { "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    return names[level <= RISK_CRITICAL ? level : RISK_NONE];
}

void X01Utf8(const WCHAR *src, char *dst, int size) {
    if (!src || !WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, size, NULL, NULL)) {
        dst[0] = 0;
    }
}

const WCHAR *X01BaseName(const WCHAR *path) {
    const WCHAR *s = wcsrchr(path, L'\\');
    return s ? s + 1 : path;
}

static void X01Lower(const WCHAR *src, WCHAR *dst, size_t size) {
    size_t i;
    for (i = 0; i + 1 < size && src[i]; ++i) {
        dst[i] = (WCHAR)towlower(src[i]);
    }
    dst[i] = 0;
}

static BOOL X01InList(const WCHAR *value, const WCHAR **list, size_t n) {
    size_t i;
    for (i = 0; value && i < n; ++i) {
        if (!_wcsicmp(value, list[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL X01HasAny(const WCHAR *lower, const WCHAR **list, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) {
        if (wcsstr(lower, list[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static const WCHAR *X01Ext(const WCHAR *name) {
    const WCHAR *d = wcsrchr(name, L'.');
    return d ? d : L"";
}

BOOL X01InWinDir(const WCHAR *path) {
    return !_wcsnicmp(path, X01WinDir, X01WinDirLen);
}

BOOL X01IsPe(const WCHAR *path) {
    return X01InList(X01Ext(X01BaseName(path)), X01PeExt, X01N(X01PeExt));
}

void X01VerdictAdd(X01Verdict *v, int points, const char *reason) {
    size_t len = strlen(v->reasons);
    v->score += points;
    snprintf(v->reasons + len, sizeof(v->reasons) - len, "%s%s", len ? "," : "", reason);
}

void X01VerdictFinish(X01Verdict *v) {
    if (v->score > 100) v->score = 100;
    v->level = v->score >= 90 ? RISK_CRITICAL :
               v->score >= 60 ? RISK_HIGH :
               v->score >= 30 ? RISK_MEDIUM :
               v->score > 0 ? RISK_LOW : RISK_NONE;
}

void X01ScoreProcess(const WCHAR *name, const WCHAR *image, const WCHAR *parent,
                     const WCHAR *cmd, X01Verdict *v) {
    WCHAR low[EDR_CMD];

    memset(v, 0, sizeof(*v));

    if (X01InList(name, X01Tools, X01N(X01Tools))) {
        X01VerdictAdd(v, 70, "known_attack_tool");
    }

    if (X01InList(name, X01Lolbins, X01N(X01Lolbins))) {
        X01VerdictAdd(v, 5, "lolbin");
        if (X01InList(parent, X01OfficeApps, X01N(X01OfficeApps))) {
            X01VerdictAdd(v, 60, "office_spawned_shell");
        }
    }

    if (image && image[0]) {
        X01Lower(image, low, X01N(low));
        if (X01HasAny(low, X01UserPaths, X01N(X01UserPaths))) {
            X01VerdictAdd(v, 25, "user_writable_path");
        }
        if (X01InList(name, X01SystemNames, X01N(X01SystemNames)) && !X01InWinDir(low)) {
            X01VerdictAdd(v, 80, "system_name_masquerade");
        }
    }

    if (cmd && cmd[0]) {
        X01Lower(cmd, low, X01N(low));
        if (X01HasAny(low, X01CmdHigh, X01N(X01CmdHigh))) {
            X01VerdictAdd(v, 80, "destructive_or_credential_cmdline");
        }
        if (X01HasAny(low, X01CmdMedium, X01N(X01CmdMedium))) {
            X01VerdictAdd(v, 35, "suspicious_cmdline");
        }
    }

    X01VerdictFinish(v);
}

static BOOL X01DoubleExt(const WCHAR *base) {
    const WCHAR *last = wcsrchr(base, L'.');
    const WCHAR *prev;
    WCHAR inner[32];
    size_t len;

    if (!last || last == base) return FALSE;
    for (prev = last - 1; prev > base && *prev != L'.'; --prev) {}
    if (*prev != L'.') return FALSE;
    len = (size_t)(last - prev);
    if (len >= X01N(inner)) return FALSE;
    wmemcpy(inner, prev, len);
    inner[len] = 0;
    return X01InList(inner, X01DocExt, X01N(X01DocExt));
}

void X01ScoreFile(const WCHAR *path, X01Verdict *v) {
    const WCHAR *base = X01BaseName(path);
    const WCHAR *ext = X01Ext(base);
    WCHAR low[EDR_PATH];
    BOOL pe = X01InList(ext, X01PeExt, X01N(X01PeExt));

    memset(v, 0, sizeof(*v));
    X01Lower(path, low, X01N(low));

    if (X01HasAny(X01BaseName(low), X01Keywords, X01N(X01Keywords))) {
        X01VerdictAdd(v, 60, "malicious_keyword");
    }
    if (wcschr(base, 0x202E)) {
        X01VerdictAdd(v, 70, "rtlo_spoofing");
    }
    if (X01InList(ext, X01ScriptExt, X01N(X01ScriptExt))) {
        X01VerdictAdd(v, 15, "script");
    }
    if (pe) {
        if (X01DoubleExt(base)) {
            X01VerdictAdd(v, 60, "double_extension");
        }
        if (X01HasAny(low, X01UserPaths, X01N(X01UserPaths))) {
            X01VerdictAdd(v, 20, "pe_user_writable_path");
        }
        if (v->score > 0 && !X01InWinDir(path) && !X01IsSigned(path)) {
            X01VerdictAdd(v, 15, "unsigned");
        }
    }

    X01VerdictFinish(v);
}

BOOL X01Sha256(const WCHAR *path, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file;
    BYTE buffer[65536];
    BYTE digest[32];
    DWORD got;
    LARGE_INTEGER size;
    BOOL ok = FALSE;
    int i;

    out[0] = 0;
    if (!X01Alg) return FALSE;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    if (GetFileSizeEx(file, &size) && size.QuadPart <= 256LL * 1024 * 1024 &&
        BCRYPT_SUCCESS(BCryptCreateHash(X01Alg, &hash, NULL, 0, NULL, 0, 0))) {
        while (ReadFile(file, buffer, sizeof(buffer), &got, NULL) && got) {
            BCryptHashData(hash, buffer, got, 0);
        }
        if (BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
            for (i = 0; i < 32; ++i) {
                out[i * 2] = hex[digest[i] >> 4];
                out[i * 2 + 1] = hex[digest[i] & 15];
            }
            out[64] = 0;
            ok = TRUE;
        }
        BCryptDestroyHash(hash);
    }

    CloseHandle(file);
    return ok;
}

BOOL X01IsSigned(const WCHAR *path) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO info;
    WINTRUST_DATA data;
    LONG status;

    memset(&info, 0, sizeof(info));
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path;

    memset(&data, 0, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);

    return status == ERROR_SUCCESS;
}
