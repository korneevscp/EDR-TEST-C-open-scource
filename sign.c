#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <wchar.h>
#include <wctype.h>
#include <stdio.h>
#include <string.h>
#include "sign.h"

#define X01SIGN_CACHE 4096

typedef struct {
    ULONGLONG key;
    X01Sign sign;
} X01SignEntry;

static X01SignEntry X01SignCache[X01SIGN_CACHE];
static CRITICAL_SECTION X01SignLock;
static BOOL X01SignReady;

typedef BOOL (WINAPI *X01CatAcquireFn)(HCATADMIN *, const GUID *, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
typedef BOOL (WINAPI *X01CatHashFn)(HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD);

static X01CatAcquireFn X01CatAcquire;
static X01CatHashFn X01CatHash;

BOOL X01SignInit(void) {
    HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");

    if (!wintrust) wintrust = LoadLibraryW(L"wintrust.dll");
    if (wintrust) {
        X01CatAcquire = (X01CatAcquireFn)(void (*)(void))GetProcAddress(wintrust, "CryptCATAdminAcquireContext2");
        X01CatHash = (X01CatHashFn)(void (*)(void))GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle2");
    }
    InitializeCriticalSection(&X01SignLock);
    X01SignReady = TRUE;
    return X01CatAcquire && X01CatHash;
}

void X01SignClose(void) {
    if (X01SignReady) {
        DeleteCriticalSection(&X01SignLock);
        X01SignReady = FALSE;
    }
}

static const char *X01SignName(X01SignStatus s) {
    static const char *names[] = { "not_checked", "unsigned", "signed", "catalog_signed", "untrusted", "invalid" };
    return names[s <= X01SIG_INVALID ? s : X01SIG_NONE];
}

BOOL X01SignTrusted(const X01Sign *s) {
    return s->status == X01SIG_EMBEDDED || s->status == X01SIG_CATALOG;
}

BOOL X01SignMicrosoft(const X01Sign *s) {
    return X01SignTrusted(s) && wcsstr(s->signer, L"Microsoft") != NULL;
}

static ULONGLONG X01SignKey(const WCHAR *path, const WIN32_FILE_ATTRIBUTE_DATA *a) {
    ULONGLONG h = 1469598103934665603ULL;

    for (; *path; ++path) {
        h = (h ^ (ULONGLONG)towlower(*path)) * 1099511628211ULL;
    }
    h = (h ^ a->ftLastWriteTime.dwLowDateTime) * 1099511628211ULL;
    h = (h ^ a->ftLastWriteTime.dwHighDateTime) * 1099511628211ULL;
    h = (h ^ a->nFileSizeLow) * 1099511628211ULL;
    return h ? h : 1;
}

static void X01Signer(HANDLE state, WCHAR *out, DWORD size) {
    CRYPT_PROVIDER_DATA *data = WTHelperProvDataFromStateData(state);
    CRYPT_PROVIDER_SGNR *signer = data ? WTHelperGetProvSignerFromChain(data, 0, FALSE, 0) : NULL;

    out[0] = 0;
    if (signer && signer->csCertChain && signer->pasCertChain && signer->pasCertChain[0].pCert) {
        CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           0, NULL, out, size);
    }
}

static LONG X01Trust(WINTRUST_DATA *data, WCHAR *signer, DWORD size) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;

    data->cbStruct = sizeof(*data);
    data->dwUIChoice = WTD_UI_NONE;
    data->fdwRevocationChecks = WTD_REVOKE_NONE;
    data->dwStateAction = WTD_STATEACTION_VERIFY;
    data->dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, data);
    if (status == ERROR_SUCCESS) {
        X01Signer(data->hWVTStateData, signer, size);
    }

    data->dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, data);
    return status;
}

static LONG X01Embedded(const WCHAR *path, WCHAR *signer, DWORD size) {
    WINTRUST_FILE_INFO info;
    WINTRUST_DATA data;

    memset(&info, 0, sizeof(info));
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path;

    memset(&data, 0, sizeof(data));
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info;
    return X01Trust(&data, signer, size);
}

static LONG X01CatalogWith(const WCHAR *path, HANDLE file, const WCHAR *alg, WCHAR *signer, DWORD size) {
    HCATADMIN admin = NULL;
    HCATINFO cat;
    CATALOG_INFO info;
    WINTRUST_CATALOG_INFO member;
    WINTRUST_DATA data;
    BYTE hash[64];
    DWORD len = sizeof(hash);
    WCHAR tag[sizeof(hash) * 2 + 1];
    LONG status = TRUST_E_NOSIGNATURE;
    DWORD i;

    if (!X01CatAcquire || !X01CatHash || !X01CatAcquire(&admin, NULL, alg, NULL, 0)) return status;

    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    if (X01CatHash(admin, file, &len, hash, 0) &&
        (cat = CryptCATAdminEnumCatalogFromHash(admin, hash, len, 0, NULL)) != NULL) {
        memset(&info, 0, sizeof(info));
        info.cbStruct = sizeof(info);
        if (CryptCATCatalogInfoFromContext(cat, &info, 0)) {
            for (i = 0; i < len; ++i) {
                _snwprintf(tag + i * 2, 3, L"%02X", hash[i]);
            }
            tag[len * 2] = 0;

            memset(&member, 0, sizeof(member));
            member.cbStruct = sizeof(member);
            member.pcwszCatalogFilePath = info.wszCatalogFile;
            member.pcwszMemberFilePath = path;
            member.pcwszMemberTag = tag;
            member.hMemberFile = file;
            member.pbCalculatedFileHash = hash;
            member.cbCalculatedFileHash = len;
            member.hCatAdmin = admin;

            memset(&data, 0, sizeof(data));
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.pCatalog = &member;
            status = X01Trust(&data, signer, size);
        }
        CryptCATAdminReleaseCatalogContext(admin, cat, 0);
    }

    CryptCATAdminReleaseContext(admin, 0);
    return status;
}

static LONG X01Catalog(const WCHAR *path, WCHAR *signer, DWORD size) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, 0, NULL);
    LONG status;

    if (file == INVALID_HANDLE_VALUE) return TRUST_E_NOSIGNATURE;
    status = X01CatalogWith(path, file, BCRYPT_SHA256_ALGORITHM, signer, size);
    if (status != ERROR_SUCCESS) {
        status = X01CatalogWith(path, file, BCRYPT_SHA1_ALGORITHM, signer, size);
    }
    CloseHandle(file);
    return status;
}

static BOOL X01NoSignature(LONG status) {
    return status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
           status == TRUST_E_PROVIDER_UNKNOWN;
}

static void X01Verify(const WCHAR *path, X01Sign *s) {
    LONG status = X01Embedded(path, s->signer, X01N(s->signer));

    if (status == ERROR_SUCCESS) {
        s->status = X01SIG_EMBEDDED;
    } else if (X01NoSignature(status)) {
        status = X01Catalog(path, s->signer, X01N(s->signer));
        s->status = status == ERROR_SUCCESS ? X01SIG_CATALOG : X01SIG_UNSIGNED;
        if (status != ERROR_SUCCESS) status = TRUST_E_NOSIGNATURE;
    } else if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST ||
               status == CERT_E_REVOKED) {
        s->status = X01SIG_INVALID;
    } else {
        s->status = X01SIG_UNTRUSTED;
    }
    s->error = status;
}

void X01SignCheck(const WCHAR *path, X01Sign *s) {
    WIN32_FILE_ATTRIBUTE_DATA attr;
    ULONGLONG key;
    X01SignEntry *slot;

    memset(s, 0, sizeof(*s));
    if (!path || !path[0] || !GetFileAttributesExW(path, GetFileExInfoStandard, &attr)) return;

    key = X01SignKey(path, &attr);
    slot = &X01SignCache[key % X01SIGN_CACHE];

    EnterCriticalSection(&X01SignLock);
    if (slot->key == key) {
        *s = slot->sign;
        LeaveCriticalSection(&X01SignLock);
        return;
    }
    LeaveCriticalSection(&X01SignLock);

    X01Verify(path, s);

    EnterCriticalSection(&X01SignLock);
    slot->key = key;
    slot->sign = *s;
    LeaveCriticalSection(&X01SignLock);
}

void X01SignJson(X01Json *j, const char *prefix, const X01Sign *s) {
    char key[64];
    char hex[16];

    if (s->status == X01SIG_NONE) return;

    snprintf(key, sizeof(key), "%s.code_signature.status", prefix);
    X01JsonStr(j, key, X01SignName(s->status));
    snprintf(key, sizeof(key), "%s.code_signature.trusted", prefix);
    X01JsonBool(j, key, X01SignTrusted(s));
    if (s->signer[0]) {
        snprintf(key, sizeof(key), "%s.code_signature.subject_name", prefix);
        X01JsonWStr(j, key, s->signer);
    }
    if (s->error) {
        snprintf(key, sizeof(key), "%s.code_signature.error", prefix);
        snprintf(hex, sizeof(hex), "0x%08lX", (unsigned long)s->error);
        X01JsonStr(j, key, hex);
    }
}
