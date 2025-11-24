#include <UnitTest++/UnitTest++.h>
#include "cipher.h"
#include <string>

std::string s = "HELLO";

SUITE(KeyTest) {
    TEST(ValidKey) {
        code cipher(5, "HELLO");
        CHECK_EQUAL("OLLEH", cipher.encryption(s));
    }
    TEST(LongKey) {
        CHECK_THROW(code(1, "HELLO"), cipher_error);
    }
}

struct KeyB_fixture {
    code * t;
    KeyB_fixture() {
        t = new code(5, "HELLO");
    }
    ~KeyB_fixture() {
        delete t;
    }
};

SUITE(EncryptTest) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input = "HELLO";
        CHECK_EQUAL("OLLEH", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input = "hello";
        CHECK_EQUAL("olleh", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        std::string input = "HELLO WORLD";
        CHECK_EQUAL("ODLLLREOHW", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        std::string input = "HELL58";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input = "";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        std::string input = "1+2+3=6";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "CLEANING");
        std::string input1 = "GNINAELC";
        std::string input2 = "CLEANING";
        CHECK_EQUAL("CLEANING", cipher.transcript(input1, input2));
    }
}

SUITE(DecryptText) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input1 = "OLLEH";
        std::string input2 = "HELLO";
        CHECK_EQUAL("HELLO", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input1 = "olleh";
        std::string input2 = "hello";
        CHECK_EQUAL("hello", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        std::string input1 = "HELLOWORLD";
        std::string input2 = "HELLO WORLD";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        std::string input1 = "HELL58";
        std::string input2 = "HELL58";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        std::string input1 = "HELLO!!!";
        std::string input2 = "HELLO!!!";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input1 = "";
        std::string input2 = "";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "Serafime");
        std::string input1 = "GNINAELC";
        std::string input2 = "CLEANING";
        CHECK_EQUAL("CLEANING", cipher.transcript(input1, input2));
    }
}

int main(int argc, char **argv) {
    return UnitTest::RunAllTests();
}