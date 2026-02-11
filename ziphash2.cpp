#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono> // For timing

// Link against the CNG library
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define CHUNK_SIZE 8192 // Increased for potentially better performance

// --- Forward Declarations ---
void show_usage();
std::wstring calculate_hash(const std::wstring& file_path, const std::wstring& alg);
std::wstring bytes_to_hex(const std::vector<BYTE>& bytes);

// --- Main Application ---
int wmain(int argc, wchar_t* argv[]) {
    std::wstring file_path;
    std::wstring alg = L"md5"; // Default algorithm

    // 1. Argument Parsing
    if (argc < 3) {
        show_usage();
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--file" && i + 1 < argc) {
            file_path = argv[++i];
        }
        else if (arg == L"--alg" && i + 1 < argc) {
            alg = argv[++i];
            // Simple validation
            if (alg != L"md5" && alg != L"sha256") {
                std::wcerr << L"Error: Invalid algorithm '" << alg << L"'. Please use 'md5' or 'sha256'." << std::endl;
                return 1;
            }
        }
    }

    if (file_path.empty()) {
        std::wcerr << L"Error: --file argument is required." << std::endl;
        show_usage();
        return 1;
    }

    if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) {
        std::wcerr << L"Error: File not found or is not a regular file: " << file_path << std::endl;
        return 1;
    }

    // 2. Calculate Hash
    try {
        auto start_time = std::chrono::high_resolution_clock::now();
        std::wstring hash_string = calculate_hash(file_path, alg);
        auto end_time = std::chrono::high_resolution_clock::now();

        if (hash_string.empty()) {
            // Error already printed in calculate_hash
            return 1;
        }

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        // 3. Output to Console
        std::wcout << L"File:       " << file_path << std::endl;
        std::wcout << L"Algorithm:  " << (alg == L"md5" ? L"MD5" : L"SHA256") << std::endl;
        std::wcout << L"Hash:       " << hash_string << std::endl;
        std::wcout << L"Time Taken: " << duration.count() << L" ms" << std::endl;

        // 4. Output to File
        std::filesystem::path fs_path(file_path);
        std::wstring output_filename = fs_path.stem().wstring() + L"_" + alg + L".txt";
        std::filesystem::path output_path = fs_path.parent_path() / output_filename;

        std::wofstream out_file(output_path);
        if (!out_file) {
            std::wcerr << L"Error: Could not open output file for writing: " << output_path << std::endl;
            return 1;
        }
        out_file << hash_string;
        out_file.close();

        std::wcout << L"Hash successfully written to: " << output_path << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected standard error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

// --- Helper Functions ---

void show_usage() {
    std::wcout << L"Usage: ziphash.exe --file <path-to-file> [--alg <md5|sha256>]" << std::endl;
    std::wcout << L"  --file    (Required) Path to the file to hash." << std::endl;
    std::wcout << L"  --alg     (Optional) Algorithm to use. Can be 'md5' or 'sha256'. Defaults to 'md5'." << std::endl;
}

std::wstring calculate_hash(const std::wstring& file_path, const std::wstring& alg) {
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cb_hash_obj = 0, cb_data = 0, cb_hash = 0;
    std::vector<BYTE> hash_obj;
    std::vector<BYTE> hash_result;

    LPCWSTR alg_id = (alg == L"md5") ? BCRYPT_MD5_ALGORITHM : BCRYPT_SHA256_ALGORITHM;

    status = BCryptOpenAlgorithmProvider(&h_alg, alg_id, NULL, 0);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"\nError: BCryptOpenAlgorithmProvider failed with status: " << std::hex << status << std::endl;
        return L"";
    }

    status = BCryptGetProperty(h_alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cb_hash_obj, sizeof(DWORD), &cb_data, 0);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"\nError: BCryptGetProperty (OBJECT_LENGTH) failed with status: " << std::hex << status << std::endl;
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return L"";
    }
    hash_obj.resize(cb_hash_obj);

    status = BCryptGetProperty(h_alg, BCRYPT_HASH_LENGTH, (PBYTE)&cb_hash, sizeof(DWORD), &cb_data, 0);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"\nError: BCryptGetProperty (HASH_LENGTH) failed with status: " << std::hex << status << std::endl;
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return L"";
    }
    hash_result.resize(cb_hash);

    status = BCryptCreateHash(h_alg, &h_hash, hash_obj.data(), cb_hash_obj, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"\nError: BCryptCreateHash failed with status: " << std::hex << status << std::endl;
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return L"";
    }

    HANDLE h_file = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h_file == INVALID_HANDLE_VALUE) {
        std::wcerr << L"\nError: Could not open file '" << file_path << L"'. Error code: " << GetLastError() << std::endl;
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return L"";
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(h_file, &file_size)) {
        std::wcerr << L"\nError: Could not get file size. Error code: " << GetLastError() << std::endl;
        CloseHandle(h_file);
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return L"";
    }

    LONGLONG total_bytes_read = 0;
    int last_progress = -1;
    std::vector<BYTE> buffer(CHUNK_SIZE);
    DWORD bytes_read = 0;

    while (ReadFile(h_file, buffer.data(), (DWORD)buffer.size(), &bytes_read, NULL) && bytes_read > 0) {
        status = BCryptHashData(h_hash, buffer.data(), bytes_read, 0);
        if (!NT_SUCCESS(status)) {
            std::wcerr << L"\nError: BCryptHashData failed with status: " << std::hex << status << std::endl;
            CloseHandle(h_file);
            BCryptDestroyHash(h_hash);
            BCryptCloseAlgorithmProvider(h_alg, 0);
            return L"";
        }

        total_bytes_read += bytes_read;
        if (file_size.QuadPart > 0) {
            int current_progress = static_cast<int>((total_bytes_read * 100) / file_size.QuadPart);
            if (current_progress > last_progress) {
                std::wcout << L"\rProgress: " << current_progress << L"% " << std::flush;
                last_progress = current_progress;
            }
        }
    }

    // Ensure 100% is displayed at the end and the line is cleared.
    std::wcout << L"\rProgress: 100% finished.                " << std::endl;


    status = BCryptFinishHash(h_hash, hash_result.data(), cb_hash, 0);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"\nError: BCryptFinishHash failed with status: " << std::hex << status << std::endl;
    }

    CloseHandle(h_file);
    BCryptDestroyHash(h_hash);
    BCryptCloseAlgorithmProvider(h_alg, 0);

    return NT_SUCCESS(status) ? bytes_to_hex(hash_result) : L"";
}

std::wstring bytes_to_hex(const std::vector<BYTE>& bytes) {
    std::wstringstream hex_stream;
    hex_stream << std::hex << std::setfill(L'0');
    for (const auto& byte : bytes) {
        hex_stream << std::setw(2) << static_cast<int>(byte);
    }
    return hex_stream.str();
}
