#include "devicehook.h"

#include <vector>

#include "avs/game.h"
#include "games/gitadora/gitadora.h"
#include "util/detour.h"
#include "util/utils.h"

#include <tlhelp32.h>
#include <map>
#include <windows.h>
#include <fstream>
#include <string>
#include <algorithm>

#include <iostream>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// std::min
#ifdef min
#undef min
#endif

namespace hooks::device {
    bool ENABLE = true;
}

bool DEVICE_CREATEFILE_DEBUG = false;
static std::string PATH_HARD_CODE_COMPARE = "d:/###-###/contents";

static decltype(ClearCommBreak) *ClearCommBreak_orig = nullptr;
static decltype(ClearCommError) *ClearCommError_orig = nullptr;
static decltype(CloseHandle) *CloseHandle_orig = nullptr;
static decltype(CreateFileA) *CreateFileA_orig = nullptr;
static decltype(CreateFileW) *CreateFileW_orig = nullptr;
static decltype(DeviceIoControl) *DeviceIoControl_orig = nullptr;
static decltype(EscapeCommFunction) *EscapeCommFunction_orig = nullptr;
static decltype(GetCommState) *GetCommState_orig = nullptr;
static decltype(GetFileSize) *GetFileSize_orig = nullptr;
static decltype(GetFileSizeEx) *GetFileSizeEx_orig = nullptr;
static decltype(GetFileInformationByHandle) *GetFileInformationByHandle_orig = nullptr;
static decltype(PurgeComm) *PurgeComm_orig = nullptr;
static decltype(ReadFile) *ReadFile_orig = nullptr;
static decltype(SetupComm) *SetupComm_orig = nullptr;
static decltype(SetCommBreak) *SetCommBreak_orig = nullptr;
static decltype(SetCommMask) *SetCommMask_orig = nullptr;
static decltype(SetCommState) *SetCommState_orig = nullptr;
static decltype(SetCommTimeouts) *SetCommTimeouts_orig = nullptr;
static decltype(WriteFile) *WriteFile_orig = nullptr;

static std::vector<CustomHandle *> CUSTOM_HANDLES;

namespace fs = std::filesystem;

class AESCrypto {
public:    
    static const int IV_SIZE = 16; // 128-bit IV

private:
    std::string key;
    std::string iv;
    static const int AES_KEY_SIZE = 256; // 256-bit AES

    // 从字符串生成固定长度的key
    std::vector<BYTE> generateFixedKey(const std::string& inputKey) {
        std::vector<BYTE> fixedKey(32); // 256-bit key = 32 bytes
        
        if (inputKey.empty()) {
            // 默认key
            std::string defaultKey = "MaoMaNiAESEncryptionKey2024";
            for (size_t i = 0; i < 32; i++) {
                fixedKey[i] = defaultKey[i % defaultKey.size()];
            }
        } else {
            // 使用PBKDF2派生密钥
            std::vector<BYTE> salt = {0x73, 0x61, 0x6C, 0x74, 0x53, 0x61, 0x6C, 0x74}; // "saltSalt"
            
            PKCS5_PBKDF2_HMAC_SHA1(
                inputKey.c_str(), inputKey.length(),
                salt.data(), salt.size(),
                10000, // 迭代次数
                32,    // 输出密钥长度
                fixedKey.data()
            );
        }
        
        return fixedKey;
    }

    // 生成随机IV
    std::vector<BYTE> generateIV() {
        std::vector<BYTE> iv(IV_SIZE);
        RAND_bytes(iv.data(), IV_SIZE);
        return iv;
    }

public:
    AESCrypto(const std::string& k = "MaoMaNi") : key(k) {
        // 生成固定长度的key和随机IV
        auto fixedKey = generateFixedKey(k);
        key = std::string(fixedKey.begin(), fixedKey.end());
        
        auto ivBytes = generateIV();
        iv = std::string(ivBytes.begin(), ivBytes.end());
    }
    
    // 获取当前IV（用于需要存储IV的情况）
    std::string getIV() const {
        return iv;
    }
    
    // 设置特定IV（用于解密已知IV的数据）
    void setIV(const std::string& newIv) {
        if (newIv.size() == IV_SIZE) {
            iv = newIv;
        }
    }
    
    // 加密数据
    bool encryptData(const BYTE* plaintext, size_t plaintext_len, 
                     std::vector<BYTE>& ciphertext) {
        try {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;
            
            // 使用AES-256-CBC模式
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                                  reinterpret_cast<const unsigned char*>(key.c_str()),
                                  reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            // 计算输出缓冲区大小（需要填充）
            ciphertext.resize(plaintext_len + AES_BLOCK_SIZE);
            int len;
            int ciphertext_len;
            
            // 加密数据
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                 plaintext, plaintext_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            ciphertext_len = len;
            
            // 完成加密（处理填充）
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            ciphertext_len += len;
            
            // 调整到实际大小
            ciphertext.resize(ciphertext_len);
            
            EVP_CIPHER_CTX_free(ctx);
            return true;
        } catch (...) {
            return false;
        }
    }
    
    // 解密数据
    bool decryptData(const BYTE* ciphertext, size_t ciphertext_len,
                     std::vector<BYTE>& plaintext) {
        try {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                  reinterpret_cast<const unsigned char*>(key.c_str()),
                                  reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            plaintext.resize(ciphertext_len);
            int len;
            int plaintext_len;
            
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                 ciphertext, ciphertext_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            plaintext_len = len;
            
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            plaintext_len += len;
            
            plaintext.resize(plaintext_len);
            
            EVP_CIPHER_CTX_free(ctx);
            return true;
        } catch (...) {
            return false;
        }
    }
    
    // 保持原有接口兼容性
    void encryptToBuffer(LPVOID lpBuffer, size_t size, size_t fileOffset = 0) {
        BYTE* data = static_cast<BYTE*>(lpBuffer);
        std::vector<BYTE> plaintext(data, data + size);
        std::vector<BYTE> ciphertext;
        
        if (encryptData(plaintext.data(), size, ciphertext)) {
            // 确保不超过原始缓冲区大小
            size_t copySize = std::min(ciphertext.size(), size);
            memcpy(data, ciphertext.data(), copySize);
            
            // 如果加密后数据更大，用0填充剩余部分
            if (copySize < size) {
                memset(data + copySize, 0, size - copySize);
            }
        }
    }
    
    void decryptFromBuffer(LPVOID lpBuffer, size_t size, size_t fileOffset = 0) {
        BYTE* data = static_cast<BYTE*>(lpBuffer);
        std::vector<BYTE> ciphertext(data, data + size);
        std::vector<BYTE> plaintext;
        
        if (decryptData(ciphertext.data(), size, plaintext)) {
            size_t copySize = std::min(plaintext.size(), size);
            memcpy(data, plaintext.data(), copySize);
            
            if (copySize < size) {
                memset(data + copySize, 0, size - copySize);
            }
        }
    }

        // 加密字符串（返回原始字节）
    std::vector<unsigned char> encryptString(const std::string& plaintext) {
        std::vector<unsigned char> plaintextBytes(plaintext.begin(), plaintext.end());
        std::vector<unsigned char> ciphertext;
        
        if (encryptData(plaintextBytes.data(), plaintextBytes.size(), ciphertext)) {
            // 返回：IV + 密文
            std::vector<unsigned char> result(iv.begin(), iv.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            return result;
        }
        
        return std::vector<unsigned char>();
    }
    
    // 解密字节数据为字符串
    std::string decryptBytes(const std::vector<unsigned char>& encryptedData) {
        if (encryptedData.size() <= IV_SIZE) {
            return "";
        }
        
        // 分离IV和密文
        std::string extractedIV(encryptedData.begin(), encryptedData.begin() + IV_SIZE);
        std::vector<unsigned char> ciphertext(encryptedData.begin() + IV_SIZE, encryptedData.end());
        
        // 设置IV
        setIV(extractedIV);
        
        // 解密
        std::vector<unsigned char> plaintext;
        if (decryptData(ciphertext.data(), ciphertext.size(), plaintext)) {
            return std::string(plaintext.begin(), plaintext.end());
        }
        
        return "";
    }

    static std::string bytesToHex(const std::vector<unsigned char>& data) {
        std::ostringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        
        for (unsigned char c : data) {
            hexStream << std::setw(2) << static_cast<int>(c);
        }
        
        return hexStream.str();
    }
    
    // HEX转字节
    static std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        
        if (hex.length() % 2 != 0) {
            return bytes;
        }
        
        bytes.reserve(hex.length() / 2);
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }

    std::string encryptFilename(const std::string& filename) {
        std::vector<unsigned char> encryptedBytes = encryptString(filename);
        if (encryptedBytes.empty()) {
            return filename;
        }
        
        return AESCrypto::bytesToHex(encryptedBytes);
    }
    
    std::string decryptFilename(const std::string& encryptedFilename) {
        std::vector<unsigned char> encryptedBytes = AESCrypto::hexToBytes(encryptedFilename);
        if (encryptedBytes.empty()) {
            return encryptedFilename;
        }
        
        std::string decryptedName = decryptBytes(encryptedBytes);
        if (decryptedName.empty()) {
            return encryptedFilename;
        }

        return decryptedName;
    }
};

// 文件加密工具类
class FileEncryptor {
private:
    AESCrypto crypto;
    
public:
    FileEncryptor(const std::string& key = "MaoMaNi") : crypto(key) {}
    
    // 加密单个文件
    bool encryptFile(const std::string& folderPath, const std::string& filePath) {
        try {
            // 读取文件
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                std::cerr << "无法打开文件: " << filePath << std::endl;
                return false;
            }
            
            file.seekg(0, std::ios::end);
            size_t fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            
            std::vector<BYTE> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
            file.close();
            
            // 加密数据
            std::vector<BYTE> encryptedData;
            if (!crypto.encryptData(buffer.data(), fileSize, encryptedData)) {
                std::cerr << "加密失败: " << filePath << std::endl;
                return false;
            }
            
            std::string encryptedPath = filePath.substr(folderPath.length());
            std::string encryptedName = crypto.encryptFilename(encryptedPath);
            std::string encryptedFullPath = folderPath + encryptedName;
            // 写入文件（添加.enc扩展名）
            std::ofstream outFile(encryptedFullPath, std::ios::binary);
            if (!outFile) {
                std::cerr << "无法创建加密文件: " << encryptedPath << std::endl;
                return false;
            }
            
            // 写入IV（前16字节）
            std::string iv = crypto.getIV();
            outFile.write(iv.c_str(), iv.size());
            
            // 写入加密数据
            outFile.write(reinterpret_cast<const char*>(encryptedData.data()), 
                         encryptedData.size());
            outFile.close();
            
            // 删除原始文件
            // fs::remove(filePath);
            
            std::cout << "加密完成: " << filePath << " -> " << encryptedPath << std::endl;
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "加密文件异常: " << filePath << " - " << e.what() << std::endl;
            return false;
        }
    }
    
    // 解密单个文件
    bool decryptFile(const std::string& folderPath, const std::string& filePath) {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                std::cerr << "无法打开文件: " << filePath << std::endl;
                return false;
            }
            

            file.seekg(0, std::ios::end);
            size_t fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            
            // 读取IV（前16字节）
            std::vector<BYTE> iv(AESCrypto::IV_SIZE);
            file.read(reinterpret_cast<char*>(iv.data()), iv.size());
            
            // 读取加密数据
            size_t dataSize = fileSize - iv.size();
            std::vector<BYTE> encryptedData(dataSize);
            file.read(reinterpret_cast<char*>(encryptedData.data()), dataSize);
            file.close();
            
            // 设置IV并解密
            crypto.setIV(std::string(iv.begin(), iv.end()));
            std::vector<BYTE> decryptedData;
            
            if (!crypto.decryptData(encryptedData.data(), dataSize, decryptedData)) {
                std::cerr << "解密失败: " << filePath << std::endl;
                return false;
            }
            
            std::string decryptedName = crypto.decryptFilename(filePath.substr(folderPath.length()));
            std::string fullPath = folderPath + fs::path(decryptedName).parent_path().generic_string();
            
            if (!fs::exists(fullPath) && fs::create_directories(fullPath)) {
                std::cerr << "无法创建目录: " << fullPath << std::endl;
                return false;
            }

            std::ofstream outFile(folderPath + decryptedName, std::ios::binary);
            
            if (!outFile) {
                std::cerr << "无法创建解密文件: " << folderPath + decryptedName << std::endl;
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(decryptedData.data()), 
                         decryptedData.size());
            outFile.close();
            
            // 删除加密文件
            // fs::remove(filePath);
            
            std::cout << "解密完成: " << filePath << " -> " << decryptedName << std::endl;
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "解密文件异常: " << filePath << " - " << e.what() << std::endl;
            return false;
        }
    }
    
    bool encryptFolder(const std::string& folderPath) {
        try {
            if (!fs::exists(folderPath) || !fs::is_directory(folderPath)) {
                std::cerr << "无效的文件夹路径: " << folderPath << std::endl;
                return false;
            }
            
            int successCount = 0;
            int totalCount = 0;

            for (const auto& entry : fs::recursive_directory_iterator(folderPath)) {
                if (fs::is_regular_file(entry.path())) {
                    totalCount++;
                    std::string filePath = entry.path().string();
                    if (encryptFile(folderPath, filePath)) {
                        successCount++;
                    }
                }
            }
            
            std::cout << "文件夹加密完成: " << folderPath << std::endl;
            std::cout << "成功: " << successCount << "/" << totalCount << " 个文件" << std::endl;
            return successCount > 0;
            
        } catch (const std::exception& e) {
            std::cerr << "遍历文件夹异常: " << folderPath << " - " << e.what() << std::endl;
            return false;
        }
    }

    // decryptFolder也要类似修改
    bool decryptFolder(const std::string& folderPath) {
        try {
            if (!fs::exists(folderPath) || !fs::is_directory(folderPath)) {
                std::cerr << "无效的文件夹路径: " << folderPath << std::endl;
                return false;
            }
            
            int successCount = 0;
            int totalCount = 0;
            
            for (const auto& entry : fs::recursive_directory_iterator(folderPath)) {
                if (fs::is_regular_file(entry.path())) {
                    std::string filePath = entry.path().string();
                    if (decryptFile(folderPath, filePath)) {
                        successCount++;
                    }
                }
            }
            
            std::cout << "文件夹解密完成: " << folderPath << std::endl;
            std::cout << "成功: " << successCount << "/" << totalCount << " 个文件" << std::endl;
            return successCount > 0;
            
        } catch (const std::exception& e) {
            std::cerr << "遍历文件夹异常: " << folderPath << " - " << e.what() << std::endl;
            return false;
        }
    }
};

AESCrypto g_AESCrypto;

MITMHandle::MITMHandle() {
    crypt_folder = L"crypt\\";
}

bool MITMHandle::open(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                      LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                      DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    std::string originalFileName = ws2s(lpFileName);

    std::wstring cryptFile = crypt_folder + s2ws(g_AESCrypto.encryptFilename(originalFileName));

    if (fs::exists(cryptFile)) {
        log_warning("devicehook", "Using encrypted file {} for {}", originalFileName, ws2s(cryptFile));
        lpFileName = cryptFile.c_str();
    }else {
        return false;
    }

    handle = CreateFileW_orig(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);

    if (handle != INVALID_HANDLE_VALUE) {
        offset[handle] = 0;
    }

    return handle != INVALID_HANDLE_VALUE;
}

int MITMHandle::read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead) {
    DWORD lpNumberOfBytesRead = 0;
    auto res = ReadFile_orig(handle, lpBuffer, nNumberOfBytesToRead,
            &lpNumberOfBytesRead, NULL);
    
    if (res) {
        if (lpNumberOfBytesRead == 0) {
            return 0;
        }
        g_AESCrypto.decryptFromBuffer(lpBuffer, lpNumberOfBytesRead, offset[handle]);
        
        offset[handle] += lpNumberOfBytesRead;
        return lpNumberOfBytesRead;
    } else {
        DWORD error = GetLastError();
        
        if (error == ERROR_HANDLE_EOF) {
            return 0;
        }

        return -1;
    }
}

int MITMHandle::write(LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite) {
    return -1;
}

int MITMHandle::device_io(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    return -1;
}

size_t MITMHandle::bytes_available() {
    COMSTAT status;
    ClearCommError_orig(handle, NULL, &status);
    return status.cbInQue;
}

bool MITMHandle::close() {
    offset[handle] = 0;
    offset.erase(handle);
    return CloseHandle_orig(handle);
}

static inline CustomHandle *get_custom_handle(HANDLE handle) {

    // TODO: we can make a custom allocator for the handles and
    //       add a simple range check instead of going through the
    //       whole list each time

    // find handle in list
    for (auto custom_handle : CUSTOM_HANDLES) {
        if (reinterpret_cast<HANDLE>(custom_handle) == handle
        || custom_handle->handle == handle) {
            return custom_handle;
        }
    }

    // no handle found - hooks will call original functions for this
    return nullptr;
}

static HANDLE WINAPI CreateFileA_hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                      DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE result = INVALID_HANDLE_VALUE;

    // convert to wide char
    WCHAR lpFileNameW[512] { 0 };
    if (!MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, lpFileNameW, std::size(lpFileNameW))) {
        return result;
    }

    // debug
    if (DEVICE_CREATEFILE_DEBUG && lpFileName != nullptr) {
        log_info("devicehook", "CreateFileA(\"{}\") => len: {}", lpFileName, strlen(lpFileName));
    }

    // check custom handles
    if (!CUSTOM_HANDLES.empty()) {
        for (auto handle : CUSTOM_HANDLES) {
            if (handle->open(lpFileNameW, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                             dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)) {
                SetLastError(0);
                if (handle->handle != INVALID_HANDLE_VALUE) {
                    result = handle->handle;
                } else {
                    result = (HANDLE) handle;
                }
                break;
            }
        }
    }

    // hard coded paths fix
    auto lpFileNameLen = wcslen(lpFileNameW);
    bool fix = true;
    for (size_t i = 0, c = 0; i < lpFileNameLen && (c = PATH_HARD_CODE_COMPARE[i]) != 0; i++) {
        if (c != '#' && lpFileName[i] != (wchar_t) PATH_HARD_CODE_COMPARE[i]) {
            fix = false;
            break;
        }
    }

    // do the fix
    if (fix && lpFileNameLen >= PATH_HARD_CODE_COMPARE.size()) {
        auto hcLen = PATH_HARD_CODE_COMPARE.size();
        auto buffer = std::make_unique<char[]>(lpFileNameLen + 1);

        buffer[0] = '.';

        for (size_t i = 0; i < lpFileNameLen - hcLen; i++) {
            buffer[i + 1] = lpFileName[hcLen + i];
        }

        if (DEVICE_CREATEFILE_DEBUG) {
            log_info("devicehook", "CreateFileA (fix): {}", buffer.get());
        }

        return CreateFileA_orig(buffer.get(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    // fallback
    if (result == INVALID_HANDLE_VALUE) {
        result = CreateFileA_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    // return result
    return result;
}

static HANDLE WINAPI CreateFileW_hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                      DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE result = INVALID_HANDLE_VALUE;

    // debug
    if (DEVICE_CREATEFILE_DEBUG && lpFileName != nullptr) {
        log_info("devicehook", "CreateFileW: {}", ws2s(lpFileName));
    }

    // check custom handles
    if (!CUSTOM_HANDLES.empty()) {
        for (auto handle : CUSTOM_HANDLES) {
            if (handle->open(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                             dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)) {
                SetLastError(0);
                if (handle->handle != INVALID_HANDLE_VALUE) {
                    result = handle->handle;
                } else {
                    result = (HANDLE) handle;
                }
                break;
            }
        }
    }

    // hard coded paths fix
    bool fix = true;
    auto lpFileNameLen = wcslen(lpFileName);
    for (size_t i = 0, c = 0; i < lpFileNameLen && (c = PATH_HARD_CODE_COMPARE[i]) != 0; i++) {
        if (c != '#' && lpFileName[i] != (wchar_t) PATH_HARD_CODE_COMPARE[i]) {
            fix = false;
            break;
        }
    }

    // do the fix
    if (fix && lpFileNameLen >= PATH_HARD_CODE_COMPARE.size()) {
        auto hcLen = PATH_HARD_CODE_COMPARE.size();
        auto buffer = std::make_unique<wchar_t[]>(lpFileNameLen + 1);

        buffer[0] = '.';

        for (size_t i = 0; i < lpFileNameLen - hcLen; i++) {
            buffer[i + 1] = lpFileName[hcLen + i];
        }

        if (DEVICE_CREATEFILE_DEBUG) {
            log_info("devicehook", "CreateFileW (fix): {}", ws2s(buffer.get()));
        }

        return CreateFileW_orig(buffer.get(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    // fallback
    if (result == INVALID_HANDLE_VALUE) {
        result = CreateFileW_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    // return result
    return result;
}

static BOOL WINAPI ReadFile_hook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
                                 LPOVERLAPPED lpOverlapped)
{
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle) {
        int value = custom_handle->read(lpBuffer, nNumberOfBytesToRead);
        if (value >= 0) {
            SetLastError(0);
            *lpNumberOfBytesRead = (DWORD) value;
            return true;
        } else {
            SetLastError(0xD);
            return false;
        }
    }

    // fallback
    return ReadFile_orig(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

static BOOL WINAPI WriteFile_hook(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                  LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle) {
        int value = custom_handle->write(lpBuffer, nNumberOfBytesToWrite);
        if (value >= 0) {
            SetLastError(0);
            *lpNumberOfBytesWritten = (DWORD) value;
            return true;
        } else {
            SetLastError(0xD);
            return false;
        }
    }

    // fallback
    return WriteFile_orig(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

static BOOL WINAPI DeviceIoControl_hook(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
                                        LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned,
                                        LPOVERLAPPED lpOverlapped)
{
    auto *custom_handle = get_custom_handle(hDevice);
    if (custom_handle) {
        int count = custom_handle->device_io(dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize);
        if (count >= 0) {
            SetLastError(0);
            *lpBytesReturned = (DWORD) count;
            if (lpOverlapped) {
                SetEvent(lpOverlapped->hEvent);
            }
            return true;
        } else {
            log_info("devicehook", "device_io failed");
            SetLastError(0xD);
            return false;
        }
    }

    // fallback
    return DeviceIoControl_orig(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize,
                                lpBytesReturned, lpOverlapped);
}

static DWORD WINAPI GetFileSize_hook(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    //log_info("devicehook", "GetFileSizeHook hit");
    return GetFileSize_orig(hFile, lpFileSizeHigh);
}

static BOOL WINAPI GetFileSizeEx_hook(HANDLE hFile, PLARGE_INTEGER lpFileSizeHigh) {
    //log_info("devicehook", "GetFileSizeExHook hit");
    return GetFileSizeEx_orig(hFile, lpFileSizeHigh);
}

static BOOL WINAPI GetFileInformationByHandle_hook(HANDLE hFile,
        LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    // custom handle
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle) {
        SetLastError(0);
        custom_handle->file_info(lpFileInformation);
        return TRUE;
    }

    return GetFileInformationByHandle_orig(hFile, lpFileInformation);
}

static BOOL WINAPI ClearCommBreak_hook(HANDLE hFile) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return ClearCommBreak_orig(hFile);
}

static BOOL WINAPI ClearCommError_hook(HANDLE hFile, LPDWORD lpErrors, LPCOMSTAT lpStat) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        if (lpStat) {
            lpStat->fXoffSent = 1;

            /*
             * Some games may check the input queue size.
             * QMA does not even attempt to read if this is set to 0.
             * We just set this to 255 and hope games do not rely on this for buffer sizes.
             *
             * Message from the future: As it turned out, some games (CCJ) do in fact rely on this value.
             */
            lpStat->cbInQue = custom_handle->bytes_available();
        }

        // gitadora arena model needs this, or else
        // the game will keep spamming 0xAA
        if (games::gitadora::is_arena_model() && lpErrors) {
            *lpErrors = 0;
        }

        return TRUE;
    }

    return ClearCommError_orig(hFile, lpErrors, lpStat);
}

static BOOL WINAPI EscapeCommFunction_hook(HANDLE hFile, DWORD dwFunc) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return EscapeCommFunction_orig(hFile, dwFunc);
}

static BOOL WINAPI GetCommState_hook(HANDLE hFile, LPDCB lpDCB) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        auto *comm_state = &custom_handle->comm_state;

        memcpy(lpDCB, comm_state, std::min(static_cast<size_t>(comm_state->DCBlength), sizeof(*comm_state)));

        return TRUE;
    }

    return GetCommState_orig(hFile, lpDCB);
}

static BOOL WINAPI PurgeComm_hook(HANDLE hFile, DWORD dwFlags) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return PurgeComm_orig(hFile, dwFlags);
}

static BOOL WINAPI SetupComm_hook(HANDLE hFile, DWORD dwInQueue, DWORD dwOutQueue) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return SetupComm_orig(hFile, dwInQueue, dwOutQueue);
}

static BOOL WINAPI SetCommBreak_hook(HANDLE hFile) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return SetCommBreak_orig(hFile);
}

static BOOL WINAPI SetCommMask_hook(HANDLE hFile, DWORD dwEvtMask) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        return TRUE;
    }

    return SetCommMask_orig(hFile, dwEvtMask);
}

static BOOL WINAPI SetCommState_hook(HANDLE hFile, LPDCB lpDCB) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle) {

        // sanity check
        if (lpDCB->DCBlength <= sizeof(custom_handle->comm_state)) {
            memcpy(&custom_handle->comm_state, lpDCB, lpDCB->DCBlength);
        }

        return TRUE;
    }

    return SetCommState_orig(hFile, lpDCB);
}

static BOOL WINAPI SetCommTimeouts_hook(HANDLE hFile, LPCOMMTIMEOUTS lpCommTimeouts) {
    auto *custom_handle = get_custom_handle(hFile);
    if (custom_handle && !custom_handle->com_pass) {
        memcpy(&custom_handle->comm_timeouts, lpCommTimeouts, sizeof(custom_handle->comm_timeouts));
        return TRUE;
    }

    return SetCommTimeouts_orig(hFile, lpCommTimeouts);
}

static BOOL WINAPI CloseHandle_hook(HANDLE hObject) {
    auto *custom_handle = get_custom_handle(hObject);
    if (custom_handle) {
        SetLastError(0);
        return custom_handle->close();
    }

    // call original
    return CloseHandle_orig(hObject);
}

static void suspend_or_resume_other_threads(bool suspending) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                if(te32.th32ThreadID == GetCurrentThreadId()) {
                    continue;
                }

                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    if (suspending) {
                        SuspendThread(hThread);
                    } else {
                        ResumeThread(hThread);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
}

void devicehook_init(HMODULE module) {
    if (!hooks::device::ENABLE) {
        return;
    }

#define STORE(value, expr) { \
    auto tmp = (expr); \
    if ((value) == nullptr) { \
        (value) = tmp; \
    } \
}

    
    // initialize only once
    static bool initialized = false;
    if (initialized) {
        return;
    } else {
        initialized = true;
        devicehook_add(new MITMHandle());
    }
    
    log_info("devicehook", "init");

    suspend_or_resume_other_threads(true);

    // IAT hooks
    STORE(ClearCommBreak_orig, detour::iat_try("ClearCommBreak", ClearCommBreak_hook, module));
    STORE(ClearCommError_orig, detour::iat_try("ClearCommError", ClearCommError_hook, module));
    STORE(CloseHandle_orig, detour::iat_try("CloseHandle", CloseHandle_hook, module));
    STORE(CreateFileA_orig, detour::iat_try("CreateFileA", CreateFileA_hook, module));
    STORE(CreateFileW_orig, detour::iat_try("CreateFileW", CreateFileW_hook, module));
    STORE(DeviceIoControl_orig, detour::iat_try("DeviceIoControl", DeviceIoControl_hook, module));
    STORE(EscapeCommFunction_orig, detour::iat_try("EscapeCommFunction", EscapeCommFunction_hook, module));
    STORE(GetCommState_orig, detour::iat_try("GetCommState", GetCommState_hook, module));
    STORE(GetFileSize_orig, detour::iat_try("GetFileSize", GetFileSize_hook, module));
    STORE(GetFileSizeEx_orig, detour::iat_try("GetFileSize", GetFileSizeEx_hook, module));
    STORE(GetFileInformationByHandle_orig, detour::iat_try(
                "GetFileInformationByHandle", GetFileInformationByHandle_hook, module));
    STORE(PurgeComm_orig, detour::iat_try("PurgeComm", PurgeComm_hook, module));
    STORE(ReadFile_orig, detour::iat_try("ReadFile", ReadFile_hook, module));
    STORE(SetupComm_orig, detour::iat_try("SetupComm", SetupComm_hook, module));
    STORE(SetCommBreak_orig, detour::iat_try("SetCommBreak", SetCommBreak_hook, module));
    STORE(SetCommMask_orig, detour::iat_try("SetCommMask", SetCommMask_hook, module));
    STORE(SetCommState_orig, detour::iat_try("SetCommState", SetCommState_hook, module));
    STORE(SetCommTimeouts_orig, detour::iat_try("SetCommTimeouts", SetCommTimeouts_hook, module));
    STORE(WriteFile_orig, detour::iat_try("WriteFile", WriteFile_hook, module));

    suspend_or_resume_other_threads(false);

#undef STORE
}

void devicehook_init_trampoline() {
    // initialize only once
    static bool initialized = false;
    if (initialized) {
        return;
    } else {
        initialized = true;
    }

    suspend_or_resume_other_threads(true);

    detour::trampoline_try("kernel32.dll", "ClearCommBreak", ClearCommBreak_hook, &ClearCommBreak_orig);
    detour::trampoline_try("kernel32.dll", "ClearCommError", ClearCommError_hook, &ClearCommError_orig);
    detour::trampoline_try("kernel32.dll", "CloseHandle", CloseHandle_hook, &CloseHandle_orig);
    detour::trampoline_try("kernel32.dll", "CreateFileA", CreateFileA_hook, &CreateFileA_orig);
    detour::trampoline_try("kernel32.dll", "CreateFileW", CreateFileW_hook, &CreateFileW_orig);
    detour::trampoline_try("kernel32.dll", "DeviceIoControl", DeviceIoControl_hook, &DeviceIoControl_orig);
    detour::trampoline_try("kernel32.dll", "EscapeCommFunction", EscapeCommFunction_hook, &EscapeCommFunction_orig);
    detour::trampoline_try("kernel32.dll", "WriteFile", WriteFile_hook, &WriteFile_orig);
    detour::trampoline_try("kernel32.dll", "GetFileSize", GetFileSize_hook, &GetFileSize_orig);
    detour::trampoline_try("kernel32.dll", "GetFileSizeEx", GetFileSizeEx_hook, &GetFileSizeEx_orig);
    detour::trampoline_try("kernel32.dll", "GetFileInformationByHandle",
                           GetFileInformationByHandle_hook, &GetFileInformationByHandle_orig);
    detour::trampoline_try("kernel32.dll", "GetCommState", GetCommState_hook, &GetCommState_orig);
    detour::trampoline_try("kernel32.dll", "PurgeComm", PurgeComm_hook, &PurgeComm_orig);
    detour::trampoline_try("kernel32.dll", "ReadFile", ReadFile_hook, &ReadFile_orig);
    detour::trampoline_try("kernel32.dll", "SetupComm", SetupComm_hook, &SetupComm_orig);
    detour::trampoline_try("kernel32.dll", "SetCommBreak", SetCommBreak_hook, &SetCommBreak_orig);
    detour::trampoline_try("kernel32.dll", "SetCommMask", SetCommMask_hook, &SetCommMask_orig);
    detour::trampoline_try("kernel32.dll", "SetCommState", SetCommState_hook, &SetCommState_orig);
    detour::trampoline_try("kernel32.dll", "SetCommTimeouts", SetCommTimeouts_hook, &SetCommTimeouts_orig);

    suspend_or_resume_other_threads(false);
}

void devicehook_add(CustomHandle *device_handle) {
    CUSTOM_HANDLES.push_back(device_handle);
}

void devicehook_dispose() {

    // clean up custom handles
    for (auto handle : CUSTOM_HANDLES) {
        delete handle;
    }
    CUSTOM_HANDLES.clear();
}
