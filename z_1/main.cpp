#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("ВУЦВУ",modAlphaCipher("ВУЦ").encrypt("ААААА"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("ВУЦПГ",modAlphaCipher("ВУЦПГУ").encrypt("ААААА"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("ВУЦВУ",modAlphaCipher("вуц").encrypt("ААААА"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("В1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("В,Г"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("В Г"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ААА"),cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("В");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("СТКДЖФОКТ", p->encrypt("ПРИВЕТМИР"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("СТКДЖФОКТ", p->encrypt("приветмир"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("СТКДЖФОКТ", p->encrypt("ПРИВЕТ,МИР!"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("УПРДЭОЕРЁРО", p->encrypt("СНОВЫМ2025ГОДОМ"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("1234+8765=9999"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ОПЗБДСЛЗП", modAlphaCipher("Я").encrypt("ПРИВЕТМИР"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ПРИВЕТМИР", p->decrypt("СТКДЖФОКТ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("сткджфокт"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("СТК ДЖФ ОКТ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("УПРДЭО2025ЕРЁРО"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("СТК,ДЖФ!ОКТ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ПРИВЕТМИР", modAlphaCipher("Я").decrypt("ОПЗБДСЛЗП"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}