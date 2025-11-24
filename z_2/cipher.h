#pragma once
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
using namespace std;

class code {
    private:
        int key;
        inline int getValidKey(int key, const string& Text);
        inline string getValidOpenText(const string& s);
        inline string getValidCipherText(const string& s, const string& open_text);
    public:
        code() = delete;
        code(int skey, string text);
        string encryption(const string& text);
        string transcript(const string& text, const string& open_text);
};

class cipher_error: public invalid_argument {
    public:
        explicit cipher_error (const string& what_arg):
            invalid_argument(what_arg) {}
        explicit cipher_error (const char* what_arg):
            invalid_argument(what_arg) {}
};