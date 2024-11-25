#include <iostream>
#include "paillier.cpp"
#include <chrono>


static PaillierPrivateKey p = PaillierPrivateKey::generateKeypair().second;
static PaillierEvaluationKey e = p.generateEvaluationKey();
/*void ZKPInSetTest(){
    std::vector<int_t> validMessages = {int_t{10}, int_t{100}, int_t{1000}, int_t{10000}, int_t{32}};
    std::cout << "Testing whether the encryption of 100 is in the array [10, 100, 1000, 10000, 32]\n";
    std::pair<int_t, std::vector<std::vector<int_t>>> cproof = p.getPublicKey().encryptWithZKPSet(int_t{32}, validMessages);
    if (p.getPublicKey().ZKPInSet(cproof.first, cproof.second.at(0), cproof.second.at(1), cproof.second.at(2), validMessages))
        std::cout << "True\n";
    else
        std::cout << "False\n";
    cproof = p.getPublicKey().encryptWithZKPSet(int_t{42}, validMessages);
    std::cout << "Testing whether the encryption of 42 is in the array [10, 100, 1000, 10000, 32]\n";
    if (p.getPublicKey().ZKPInSet(cproof.first, cproof.second.at(0), cproof.second.at(1), cproof.second.at(2), validMessages))
        std::cout << "True\n";
    else
        std::cout << "False\n";
}*/
void genericTest(){
    std::cout << "Encryption of -123: " << p.getPublicKey().encrypt(int_t{123}) << "\n";
    //std:: cout<<"Compare 1 2 \n" << e.compare(p.getPublicKey().encrypt(int_t{1}),p.getPublicKey().encrypt(int_t{2}))<< "\n";
    //std:: cout<<"Compare 2 1 \n" << e.compare(p.getPublicKey().encrypt(int_t{2}),p.getPublicKey().encrypt(int_t{1}))<< "\n";
    //std:: cout<<"Compare 2 4 \n" << e.compare(p.getPublicKey().encrypt(int_t{2}),p.getPublicKey().encrypt(int_t{4}))<< "\n";
    //std:: cout<<"Compare 2 2 \n" << e.compare(p.getPublicKey().encrypt(int_t{2}),p.getPublicKey().encrypt(int_t{2}))<< "\n";
    std::cout << "Decryption of (#123): " << p.decrypt(p.getPublicKey().encrypt(int_t{123})) << "\n";
    //std::cout << "Decryption of (#123-#12): " << p.decrypt(PaillierPublicKey::sub(p.getPublicKey().encrypt(int_t{123}), p.getPublicKey().encrypt(int_t{12}), p.getPublicKey())) << "\n";
    //std::cout << "Decryption of (#124-#123): " << p.decrypt(PaillierPublicKey::sub(p.getPublicKey().encrypt(int_t{124}), p.getPublicKey().encrypt(int_t{123}), p.getPublicKey())) << "\n";
    //std::cout << "Decryption of (#123-#124): " << p.decrypt(PaillierPublicKey::sub(p.getPublicKey().encrypt(int_t{123}), p.getPublicKey().encrypt(int_t{124}), p.getPublicKey())) << "\n";
    //std::cout << "Decryption of (#-123-#124): " << p.decrypt(PaillierPublicKey::sub(p.getPublicKey().encrypt(int_t{-123}), p.getPublicKey().encrypt(int_t{124}), p.getPublicKey())) << "\n";
    //std::cout << "Decryption of (#-1-#2): " << p.decrypt(PaillierPublicKey::add(p.getPublicKey().encrypt(int_t{-1}),p.getPublicKey().encrypt(int_t{-2}), p.getPublicKey())) << "\n";
    //std::cout << "Decryption of (#123+1): " << p.decrypt(p.getPublicKey().raw_add(p.getPublicKey().encrypt(int_t{123}), int_t{1})) << "\n";
    //std::cout << "Decryption of (#123·4): " << p.decrypt(PaillierPublicKey::mul(p.getPublicKey().encrypt(int_t{123}), int_t{4}, p.getPublicKey())) << "\n";
    //std::cout << "Public key in JSON format:\n" << p.getPublicKey().to_string() << "\n";
    //std::cout << "Private key in JSON format:\n" << p.to_string() << "\n";
    //const std::pair<int_t, int_t> signature = p.sign(int_t{333});
    //std::cout << "Verifying signature (must return True):\n" << (p.getPublicKey().verifySignature(int_t{333}, signature)?"True":"False") << "\n";
}

int_t random_int(int_t min, int_t max) {
    return rand() % (max - min + 1) + min;
}

void test_encryption_subtraction(int num_tests = 1000) {
    int correct_count = 0;  // Counter for the correct results
    srand(static_cast<unsigned int>(time(0)));  // Seed the random number generator

    for (int i = 0; i < num_tests; ++i) {
        // Step 1: Randomly generate two integers
        int_t m1 = random_int(-100, -1);  // Example range [1, 100], adjust as needed
        int_t m2 = random_int(-100, -1);

        // Step 2: Determine the larger and smaller integers
        int_t larger = std::max(m1, m2);
        int_t smaller = std::min(m1, m2);

        // Step 3: Perform homomorphic subtraction (larger - smaller)
        int_t encrypted_result = PaillierPublicKey::sub(p.getPublicKey().encrypt(smaller), p.getPublicKey().encrypt(larger), p.getPublicKey());

        // Step 4: Decrypt the result
        int_t decrypted_result = p.decrypt(encrypted_result);

        // Step 5: Compare the decrypted result with the expected plaintext result
        int_t expected_result = smaller - larger;

        if (decrypted_result == expected_result) {
            correct_count++;
        }
        std::cout << "Decryption result of : " << decrypted_result << "\n";
    }

    // Output the number of correct results
    std::cout << "Number of correct results: " << correct_count << " out of " << num_tests << std::endl;
}
void test_encryption_add(int num_tests = 1000) {
    int correct_count = 0;  // Counter for the correct results
    srand(static_cast<unsigned int>(time(0)));  // Seed the random number generator

    for (int i = 0; i < num_tests; ++i) {
        // Step 1: Randomly generate two integers
        int_t m1 = random_int(-100, -1);  // random number between [-100, -1]
        int_t m2 = random_int(-100, -1);

        // Step 2: Perform homomorphic subtraction (larger - smaller)
        int_t encrypted_result = PaillierPublicKey::add(p.getPublicKey().encrypt(m1), p.getPublicKey().encrypt(m2), p.getPublicKey());

        // Step 3: Decrypt the result
        int_t decrypted_result = p.decrypt(encrypted_result);

        // Step 4: Compare the decrypted result with the expected plaintext result
        int_t expected_result = m1 + m2;

        if (decrypted_result == expected_result) {
            correct_count++;
        }
    }

    // Output the number of correct results
    std::cout << "Number of correct results: " << correct_count << " out of " << num_tests << std::endl;
}
void test_encryption_compare(int num_tests = 1000) {
    srand(static_cast<unsigned int>(time(0)));  // Seed the random number generator
    int correct_count = 0;  // Counter for the correct results
    for (int i = 0; i < num_tests; ++i) {
        PaillierPrivateKey prk = PaillierPrivateKey::generateKeypair().second;
        PaillierEvaluationKey ek = prk.generateEvaluationKey();
        // Step 1: Randomly generate two integers
        int_t m1 = random_int(-100, 100);  // random number between [-100, -1]
        int_t m2 = random_int(-100, 100);
        int_t compare_result = ek.compare(prk.getPublicKey().encrypt(m1), prk.getPublicKey().encrypt(m2));
        std::cout << "compare result of m1:" << m1 << "  & m2:" << m2 << " is:" << compare_result << "\n";
        if (compare_result * (m1-m2) >=0) {
            correct_count++;
        }
    }

    // Output the number of correct results
    std::cout << "Number of correct results: " << correct_count << " out of " << num_tests << std::endl;
}
void test_time() {
        // 测量加密时间
    auto encryptStart = std::chrono::high_resolution_clock::now();
    int_t cipher1 = p.getPublicKey().encrypt(int_t{123});
    auto encryptEnd = std::chrono::high_resolution_clock::now();
    auto encryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(encryptEnd - encryptStart).count();
    std::cout << "Encryption time: " << encryptDuration << " microseconds" << "\n";
    auto decryptStart = std::chrono::high_resolution_clock::now();
    p.decrypt(cipher1);
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    auto decryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(decryptEnd - decryptStart).count();
    std::cout << "Decryption time: " << decryptDuration << " microseconds" << "\n";
    int_t cipher2 = p.getPublicKey().encrypt(int_t{12});
    auto compareStart = std::chrono::high_resolution_clock::now();
    e.compare(cipher1, cipher2);
    auto compareEnd = std::chrono::high_resolution_clock::now();
    auto compareDuration = std::chrono::duration_cast<std::chrono::microseconds>(compareEnd - compareStart).count();
    std::cout << "Compare time: " << compareDuration << " microseconds" << "\n";
}
/*void ZKPCorrectDecryptionTest(){
    std::cout << "Testing whether (#555-#555) is an encryption of 0 (must return True):\n" << (p.ZKPCorrectDecryption(p.getPublicKey().encrypt(int_t{555}), int_t{555},getRandomNumber(PaillierPublicKey::DEFAULT_KEYSIZE-1))?"True":"False") << "\n";
    std::cout << "Testing whether (#555-#554) is an encryption of 0 (must return False):\n" << (p.ZKPCorrectDecryption(p.getPublicKey().encrypt(int_t{555}), int_t{554},getRandomNumber(PaillierPublicKey::DEFAULT_KEYSIZE-1))?"True":"False") << "\n";
}*/
int main(){
    std::ios_base::sync_with_stdio(false);
    genericTest();
    //ZKPInSetTest();
    //ZKPCorrectDecryptionTest();
    //test_encryption_subtraction(10); // larger one - small one
    //test_encryption_add(500); //both number are negative
    //test_encryption_compare(30);
    test_time();
}
