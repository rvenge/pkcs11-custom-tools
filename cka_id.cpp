#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <cctype>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include "include/pkcs11/cryptoki.h" // requires 

// Sample program to modify CKA_ID of an object protected by a PKCS#11 Token. 

// Function to load PKCS#11 library and get function list
CK_FUNCTION_LIST_PTR loadPKCS11Library() {
    CK_FUNCTION_LIST_PTR pFunctionList = nullptr;
    
#ifdef _WIN32
    HMODULE hModule = LoadLibraryA("C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll");
    if (!hModule) {
        std::cerr << "Failed to load PKCS#11 library" << std::endl;
        return nullptr;
    }
    
    CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
#else
    void* hModule = dlopen("/opt/nfast/toolkits/pkcs11/libcknfast.so", RTLD_LAZY);
    if (!hModule) {
        std::cerr << "Failed to load PKCS#11 library: " << dlerror() << std::endl;
        return nullptr;
    }
    
    CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)dlsym(hModule, "C_GetFunctionList");
#endif

    if (!pC_GetFunctionList) {
        std::cerr << "Failed to get C_GetFunctionList function" << std::endl;
        return nullptr;
    }
    
    CK_RV rv = pC_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        std::cerr << "C_GetFunctionList failed: " << std::hex << rv << std::endl;
        return nullptr;
    }
    
    return pFunctionList;
}

// Function to print hex data
void printHex(const std::vector<CK_BYTE>& data, const std::string& label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i < data.size() - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

// Function to get object's CKA_ID
std::vector<CK_BYTE> getCKA_ID(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    CK_ATTRIBUTE template_attr[] = {
        {CKA_ID, nullptr, 0}
    };
    
    CK_RV rv = pFunctionList->C_GetAttributeValue(hSession, hObject, template_attr, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get CKA_ID length: " << std::hex << rv << std::endl;
        return {};
    }
    
    std::vector<CK_BYTE> cka_id(template_attr[0].ulValueLen);
    template_attr[0].pValue = cka_id.data();
    
    rv = pFunctionList->C_GetAttributeValue(hSession, hObject, template_attr, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get CKA_ID value: " << std::hex << rv << std::endl;
        return {};
    }
    
    return cka_id;
}

// Function to convert object class string to CK_OBJECT_CLASS
CK_OBJECT_CLASS getObjectClass(const std::string& classStr) {
    std::string lowerClass = classStr;
    std::transform(lowerClass.begin(), lowerClass.end(), lowerClass.begin(), ::tolower);
    
    if (lowerClass == "private") {
        return CKO_PRIVATE_KEY;
    } else if (lowerClass == "public") {
        return CKO_PUBLIC_KEY;
    } else if (lowerClass == "secret") {
        return CKO_SECRET_KEY;
    } else {
        return (CK_OBJECT_CLASS)-1; // Invalid class
    }
}

// Function to find object by class and label
CK_OBJECT_HANDLE findObjectByClassAndLabel(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, 
                                          CK_OBJECT_CLASS objectClass, const std::string& label) {
    CK_ATTRIBUTE template_attr[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_LABEL, (CK_VOID_PTR)label.c_str(), (CK_ULONG)label.length()}
    };
    
    CK_RV rv = pFunctionList->C_FindObjectsInit(hSession, template_attr, 2);
    if (rv != CKR_OK) {
        std::cerr << "C_FindObjectsInit failed: " << std::hex << rv << std::endl;
        return CK_INVALID_HANDLE;
    }
    
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    rv = pFunctionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
    if (rv != CKR_OK) {
        std::cerr << "C_FindObjects failed: " << std::hex << rv << std::endl;
        pFunctionList->C_FindObjectsFinal(hSession);
        return CK_INVALID_HANDLE;
    }
    
    pFunctionList->C_FindObjectsFinal(hSession);
    
    if (ulObjectCount == 0) {
        return CK_INVALID_HANDLE;
    }
    
    return hObject;
}

int main() {
    // Set environment variables for nCipher
    _putenv("CKNFAST_FAKE_ACCELERATOR_LOGIN=1"); // Required for module protection
    _putenv("CKNFAST_LOADSHARING=1"); // Enables load sharing and softcard slots
    //_putenv("CKNFAST_DEBUG=10"); // Uncomment for debug logs
    //_putenv("NFAST_DEBUGFILE=/path/to/debug.log"); // Uncomment to set debug log file
    
    CK_FUNCTION_LIST_PTR pFunctionList = loadPKCS11Library();
    if (!pFunctionList) {
        return 1;
    }
    
    // Initialize PKCS#11
    CK_RV rv = pFunctionList->C_Initialize(nullptr);
    if (rv != CKR_OK) {
        std::cerr << "C_Initialize failed: " << std::hex << rv << std::endl;
        return 1;
    }
    
    // Open session on slot 0
    CK_SESSION_HANDLE hSession;
    rv = pFunctionList->C_OpenSession(761406613, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession); // 761406613 = Slot 0, 761406614 = Slot 1, 761406615= Slot 2, etc. 
    if (rv != CKR_OK) {
        std::cerr << "C_OpenSession failed: " << std::hex << rv << std::endl;
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
    
    // Login as user with default PIN
    std::string pin = "1234";
    rv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pin.c_str(), pin.length());
    if (rv != CKR_OK) {
        std::cerr << "C_Login failed: " << std::hex << rv << std::endl;
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
    
    std::cout << "Successfully logged in to slot 0" << std::endl;
    
    // Get object class from user
    std::string classInput;
    std::cout << "Enter object class (private/public/secret): ";
    std::cin >> classInput;
    
    CK_OBJECT_CLASS objectClass = getObjectClass(classInput);
    if (objectClass == (CK_OBJECT_CLASS)-1) {
        std::cerr << "Invalid object class. Must be 'private', 'public', or 'secret'" << std::endl;
        pFunctionList->C_Logout(hSession);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
    
    // Get object label from user
    std::string label;
    std::cout << "Enter object label: ";
    std::cin >> label;
    
    // Find the object
    CK_OBJECT_HANDLE hObject = findObjectByClassAndLabel(pFunctionList, hSession, objectClass, label);
    if (hObject == CK_INVALID_HANDLE) {
        std::cerr << "Object with class '" << classInput << "' and label '" << label << "' not found" << std::endl;
        pFunctionList->C_Logout(hSession);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
    
    std::cout << "Found object with class '" << classInput << "' and label '" << label << "'" << std::endl;
    
    // Get current CKA_ID
    std::vector<CK_BYTE> oldCKA_ID = getCKA_ID(pFunctionList, hSession, hObject);
    if (oldCKA_ID.empty()) {
        std::cout << "Object has no current CKA_ID or failed to retrieve it" << std::endl;
    } else {
        printHex(oldCKA_ID, "Current CKA_ID");
    }
    
    // Get new CKA_ID from user
    std::cout << "Enter new CKA_ID (hex format, e.g., 01234567abcdef): ";
    std::string hexInput;
    std::cin >> hexInput;
    
    // Convert hex string to bytes
    std::vector<CK_BYTE> newCKA_ID;
    for (size_t i = 0; i < hexInput.length(); i += 2) {
        if (i + 1 < hexInput.length()) {
            std::string byteString = hexInput.substr(i, 2);
            CK_BYTE byte = (CK_BYTE)strtol(byteString.c_str(), nullptr, 16);
            newCKA_ID.push_back(byte);
        }
    }
    
    if (newCKA_ID.empty()) {
        std::cerr << "Invalid hex input" << std::endl;
        pFunctionList->C_Logout(hSession);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
    
    // Modify CKA_ID
    CK_ATTRIBUTE template_attr[] = {
        {CKA_ID, newCKA_ID.data(), (CK_ULONG)newCKA_ID.size()}
    };
    
    rv = pFunctionList->C_SetAttributeValue(hSession, hObject, template_attr, 1);
    if (rv != CKR_OK) {
        std::cerr << "C_SetAttributeValue failed: " << std::hex << rv << std::endl;
        pFunctionList->C_Logout(hSession);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return 1;
    }
        
    // Verify the change
    std::vector<CK_BYTE> verifiedCKA_ID = getCKA_ID(pFunctionList, hSession, hObject);
    
    std::cout << "\nCKA_ID Modification Summary" << std::endl;
    std::cout << "Object Class: " << classInput << std::endl;
    std::cout << "Object Label: " << label << std::endl;
    if (!oldCKA_ID.empty()) {
        printHex(oldCKA_ID, "Old CKA_ID");
    } else {
        std::cout << "Old CKA_ID: (none)" << std::endl;
    }
    printHex(newCKA_ID, "New CKA_ID (requested)");
    printHex(verifiedCKA_ID, "New CKA_ID (verified)");
    
    // Check if modification was successful
    if (verifiedCKA_ID == newCKA_ID) {
        std::cout << "CKA_ID modification successful" << std::endl;
    } else {
        std::cout << "CKA_ID modification verification failed" << std::endl;
    }
    
    // Cleanup
    pFunctionList->C_Logout(hSession);
    pFunctionList->C_CloseSession(hSession);
    pFunctionList->C_Finalize(nullptr);
    
    return 0;
}
