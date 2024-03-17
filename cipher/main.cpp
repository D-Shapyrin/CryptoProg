#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

using namespace CryptoPP;
using namespace std;

void EncryptFile(const string& fileName, const string& password) {
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string encryptedFile = fileName + ".enc"; // New file with encoded text
    string ivFile = fileName + ".iv"; // New IV file
    string keyFile = fileName + ".key"; // New key file
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), iv);

    // Write output file
    ofstream outputFile(encryptedFile, ios::binary);
    if (!outputFile) {
        cerr << "Error: Failed to open output file for writing." << endl;
        return;
    }

    FileSource fs(fileName.c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFile)));

    // Write IV to separate file
    ofstream ivOutputFile(ivFile, ios::binary);
    if (!ivOutputFile) {
        cerr << "Error: Failed to open IV output file for writing." << endl;
        return;
    }

    ivOutputFile.write(reinterpret_cast<const char*>(iv), AES::BLOCKSIZE);

    // Write key to separate file
    ofstream keyOutputFile(keyFile, ios::binary);
    if (!keyOutputFile) {
        cerr << "Error: Failed to open key output file for writing." << endl;
        return;
    }

    keyOutputFile.write(reinterpret_cast<const char*>(key.BytePtr()), key.size());

    outputFile.close();
    ivOutputFile.close();
    keyOutputFile.close();

    // Output contents of encryptedFile
    cout << "Contents of encrypted file (" << encryptedFile << "):" << endl;
    ifstream encryptedInputFile(encryptedFile, ios::binary);
    cout << encryptedInputFile.rdbuf() << endl;

    // Output contents of ivFile
    cout << "Contents of IV file (" << ivFile << "):" << endl;
    ifstream ivOpenOutputFile(ivFile, ios::binary);
    cout << ivOpenOutputFile.rdbuf() << endl;

    // Output contents of keyFile
    cout << "Contents of key file (" << keyFile << "):" << endl;
    ifstream keyOpenOutputFile(keyFile, ios::binary);
    cout << keyOpenOutputFile.rdbuf() << endl;

    outputFile.close();
    ivOutputFile.close();
    keyOutputFile.close();
}

void DecryptFile(const string& fileName, const string& ivFile, const string& keyFile, const string& password) {
    string decryptedFile = fileName.substr(0, fileName.find_last_of('.')); // Убираем расширение >> decryptedFile = txt
    CBC_Mode<AES>::Decryption decryption;

    // Read IV from separate file
    ifstream ivInputFile(ivFile, ios::binary);
    if (!ivInputFile.is_open()) {
        cerr << "Error: Failed to open IV input file for reading." << endl;
        return;
    }

    // Output contents of ivInputFile
    cout << "Contents of IV file (" << ivFile << "):" << endl;
    cout << ivInputFile.rdbuf() << endl;
    ivInputFile.seekg(0, ios::beg);

    CryptoPP::byte iv[AES::BLOCKSIZE];
    ivInputFile.read(reinterpret_cast<char*>(iv), AES::BLOCKSIZE);
    ivInputFile.seekg(0, ios::beg); // Возврат к началу файла
    if (ivInputFile.gcount() != AES::BLOCKSIZE) {
        cerr << "Error: Failed to read IV from file." << endl;
        return;
    }

    // Read key from separate file
    ifstream keyInputFile(keyFile, ios::binary);
    if (!keyInputFile.is_open()) {
        cerr << "Error: Failed to open key input file for reading." << endl;
        return;
    }

    // Output contents of keyInputFile
    cout << "Contents of key file (" << keyFile << "):" << endl;
    cout << keyInputFile.rdbuf() << endl;
    keyInputFile.seekg(0, ios::beg); // Возврат к началу файла

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    keyInputFile.read(reinterpret_cast<char*>(key.BytePtr()), key.size());
    if (keyInputFile.gcount() != AES::DEFAULT_KEYLENGTH) {
        cerr << "Error: Failed to read key from file." << endl;
        return;
    }

    // Set decryption key and IV
    decryption.SetKeyWithIV(key, key.size(), iv);

    // Open encrypted file
    ifstream inputFile(fileName, ios::binary);
    if (!inputFile) {
        cerr << "Error: Failed to open input file for reading." << endl;
        return;
    }

    // Output contents of encryptedFile
    cout << "Contents of crypted file (" << fileName << "):" << endl;
    cout << inputFile.rdbuf() << endl;
    inputFile.seekg(0, ios::beg);

    // Open output file for writing decrypted data
    ofstream outputFile(decryptedFile, ios::binary);
    if (!outputFile) {
        cerr << "Error: Failed to open output file for writing." << endl;
        return;
    }

    // Decrypt the ciphertext
    FileSource fs(inputFile, true, new StreamTransformationFilter(decryption, new FileSink(outputFile)));

    outputFile.close();
    inputFile.close();
    keyInputFile.close();
    ivInputFile.close();
}

int main() {
    int choice;
    string fileName, ivFile, keyFile, password;

    cout << "Select mode:\n";
    cout << "1. Encryption\n";
    cout << "2. Decryption\n";
    cin >> choice;

    password = "123";
    cout << "Password: " << password << endl;

    switch (choice) {
        case 1:
            fileName = "txt";
            cout << "\nFile name: " << fileName << endl;
            EncryptFile(fileName, password);
            cout << "\nFile encrypted successfully.\n";
            break;
        case 2:
            fileName = "txt.enc";
            ivFile = "txt.iv";
            keyFile = "txt.key";
            cout << "\nFile name: " << fileName << endl;
            DecryptFile(fileName, ivFile, keyFile, password);
            cout << "\nFile decrypted successfully.\n";
            break;
        default:
            cout << "Invalid choice.\n";
            break;
    }

    return 0;
}
