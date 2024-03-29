#include <cryptopp/cryptlib.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

int main() {
    string hsh, msg, result, result1;
    FileSource("/home/hozz/Desktop/CryptoProg/hash2/text", true, new StringSink(msg));
    msg.resize(msg.size() - 1);
    cout << "Текст: " << msg << endl;
    HexEncoder encoder(new StringSink(result));
    Weak::MD5 hash;
    hash.Update((const CryptoPP::byte*)&msg[0], msg.size());
    hsh.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&hsh[0]);
    cout << "HASH: ";
    StringSource(hsh, true, new Redirector(encoder));
    cout << result << "\n\n";
    
    HexEncoder encoder1(new StringSink(result1));
    string hsh1, msg1 = "123";
    cout << "Text: " << msg1 << endl;
    hash.Update((const CryptoPP::byte*)&msg1[0], msg1.size());
    hsh1.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&hsh1[0]);
    cout << "HASH: ";
    StringSource(hsh1, true, new Redirector(encoder1));
    cout << result1 << endl;
    if (result == result1)
        cout << "Успешно\n";
}
