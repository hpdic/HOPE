#include <iostream>
#include <string>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <chrono>  // 引入chrono库用于时间测量

using namespace CryptoPP;
using namespace std;
using namespace chrono;  // 使用chrono命名空间

void AES_Encrypt(int plaintextInt, const SecByteBlock& key, const SecByteBlock& iv, string& ciphertext) {
    // 将整数转换为字符串
    string plaintext = to_string(plaintextInt);

    try {
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );
    } catch (const Exception& e) {
        cerr << "Encryption error: " << e.what() << endl;
    }
}

void AES_Decrypt(const string& ciphertext, const SecByteBlock& key, const SecByteBlock& iv, int& decryptedInt) {
    string decryptedText;

    try {
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedText)
            )
        );

        // 将解密后的字符串转换为整数
        decryptedInt = stoi(decryptedText);
    } catch (const Exception& e) {
        cerr << "Decryption error: " << e.what() << endl;
    } catch (const invalid_argument&) {
        cerr << "Invalid decrypted text to integer conversion." << endl;
    }
}

int main() {
    AutoSeededRandomPool prng;

    // Key and IV generation
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());

    int plaintextInt = 12345;  // 要加密的整数
    string ciphertext;
    int decryptedInt = 0;

    cout << "Original integer: " << plaintextInt << endl;

    // 测量加密时间
    auto encryptStart = high_resolution_clock::now();
    AES_Encrypt(plaintextInt, key, iv, ciphertext);
    auto encryptEnd = high_resolution_clock::now();
    auto encryptDuration = duration_cast<microseconds>(encryptEnd - encryptStart).count();
    cout << "Encryption time: " << encryptDuration << " microseconds" << endl;

    // Convert ciphertext to hex for display
    string encoded;
    StringSource(ciphertext, true, new HexEncoder(new StringSink(encoded)));
    cout << "Ciphertext (in hex): " << encoded << endl;

    // 测量解密时间
    auto decryptStart = high_resolution_clock::now();
    AES_Decrypt(ciphertext, key, iv, decryptedInt);
    auto decryptEnd = high_resolution_clock::now();
    auto decryptDuration = duration_cast<microseconds>(decryptEnd - decryptStart).count();
    cout << "Decryption time: " << decryptDuration << " microseconds" << endl;

    cout << "Decrypted integer: " << decryptedInt << endl;

    return 0;
}