#include "anre/SignatureChecker.hpp"

#include <mutex>
#include <unordered_map>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace anre {

#ifdef _WIN32
namespace {

std::wstring toWide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, result.data(), length);
    return result;
}

std::string toUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, result.data(), length, nullptr, nullptr);
    return result;
}

const HWND kNoWindow = reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);

// Pull the signer's display name out of a PKCS#7-signed file (an .exe with an
// embedded signature, or a security-catalog .cat).
std::string publisherFrom(const std::wstring& signedFilePath) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            signedFilePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, nullptr, nullptr, nullptr, &store, &message, nullptr)) {
        return {};
    }

    std::string publisher;
    DWORD signerSize = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) &&
        signerSize > 0 && signerSize < 16u * 1024 * 1024) {
        std::vector<BYTE> signerBuffer(signerSize);
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(), &signerSize)) {
            auto* signer = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuffer.data());
            CERT_INFO certInfo{};
            certInfo.Issuer = signer->Issuer;
            certInfo.SerialNumber = signer->SerialNumber;

            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certInfo,
                nullptr);
            if (cert != nullptr) {
                const DWORD needed = CertGetNameStringW(
                    cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                if (needed > 1) {
                    std::wstring name(needed, L'\0');
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), needed);
                    name.resize(wcslen(name.c_str()));
                    publisher = toUtf8(name);
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (message != nullptr) {
        CryptMsgClose(message);
    }
    if (store != nullptr) {
        CertCloseStore(store, 0);
    }
    return publisher;
}

LONG verifyEmbedded(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(kNoWindow, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(kNoWindow, &action, &data);
    return status;
}

// Many legitimate Windows binaries carry no embedded signature — they're signed
// by hash in a system security catalog instead. Without this fallback every one
// of them would look "unsigned", which is exactly the kind of false positive
// Ghostwire is trying to avoid.
SignatureStatus verifyCatalog(const std::wstring& path, std::string& publisherOut) {
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return SignatureStatus::Unknown;
    }

    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext(&admin, nullptr, 0)) {
        CloseHandle(file);
        return SignatureStatus::Unsigned;
    }

    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle(file, &hashSize, nullptr, 0);
    if (hashSize == 0 || hashSize > 4096) { // a file hash is tens of bytes; anything else is bogus
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
        return SignatureStatus::Unsigned;
    }
    std::vector<BYTE> hash(hashSize);
    if (!CryptCATAdminCalcHashFromFileHandle(file, &hashSize, hash.data(), 0)) {
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
        return SignatureStatus::Unsigned;
    }

    SignatureStatus status = SignatureStatus::Unsigned;
    HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashSize, 0, nullptr);
    if (catalog != nullptr) {
        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        if (CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0)) {
            std::wstring memberTag;
            memberTag.reserve(hashSize * 2);
            for (DWORD i = 0; i < hashSize; ++i) {
                wchar_t hex[3];
                swprintf(hex, 3, L"%02X", hash[i]);
                memberTag += hex;
            }

            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
            wci.pcwszMemberFilePath = path.c_str();
            wci.pcwszMemberTag = memberTag.c_str();
            wci.pbCalculatedFileHash = hash.data();
            wci.cbCalculatedFileHash = hashSize;
            wci.hMemberFile = file;

            WINTRUST_DATA wd{};
            wd.cbStruct = sizeof(wd);
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_CATALOG;
            wd.pCatalog = &wci;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;
            wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG result = WinVerifyTrust(kNoWindow, &action, &wd);
            status = (result == ERROR_SUCCESS)
                ? SignatureStatus::SignedTrusted
                : SignatureStatus::SignedUntrusted;

            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(kNoWindow, &action, &wd);

            if (status == SignatureStatus::SignedTrusted) {
                publisherOut = publisherFrom(catalogInfo.wszCatalogFile);
            }
        }
        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
    }

    CryptCATAdminReleaseContext(admin, 0);
    CloseHandle(file);
    return status;
}

std::mutex g_cacheMutex;
std::unordered_map<std::string, SignatureInfo> g_cache;

} // namespace

SignatureInfo SignatureChecker::check(const std::string& imagePath) {
    if (imagePath.empty()) {
        return {};
    }

    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        const auto it = g_cache.find(imagePath);
        if (it != g_cache.end()) {
            return it->second;
        }
    }

    const std::wstring wide = toWide(imagePath);
    SignatureInfo info;

    const LONG embedded = verifyEmbedded(wide);
    if (embedded == ERROR_SUCCESS) {
        info.status = SignatureStatus::SignedTrusted;
        info.publisher = publisherFrom(wide);
    } else if (embedded == TRUST_E_NOSIGNATURE) {
        // No embedded signature — it may still be catalog-signed by the OS.
        info.status = verifyCatalog(wide, info.publisher);
    } else {
        // Signed, but the trust chain didn't validate (expired, self-signed,
        // revoked, tampered). Treat as present-but-untrusted.
        info.status = SignatureStatus::SignedUntrusted;
        info.publisher = publisherFrom(wide);
    }

    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_cache[imagePath] = info;
    }
    return info;
}

bool SignatureChecker::available() {
    return true;
}

#else // !_WIN32

SignatureInfo SignatureChecker::check(const std::string&) {
    return {};
}

bool SignatureChecker::available() {
    return false;
}

#endif

} // namespace anre
