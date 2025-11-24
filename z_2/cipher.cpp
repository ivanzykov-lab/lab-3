#include "cipher.h"

code::code(int skey, string text) {
    key = getValidKey(skey, text);
}

string code::encryption(const string& text) {
    string t = getValidOpenText(text);
    int k = 0;
    int simvoli = t.size();
    int stroki = simvoli / key;
    char** tabl = new char* [stroki];
    for (int i = 0; i < stroki; i++)
        tabl[i] = new char [key];

    for (int i = 0; i < stroki; i++)
        for (int j = 0; j < key; j++) {
            if(k < simvoli) {
                tabl[i][j] = t[k];
                k++;
            }
        }

    k = 0;
    for (int j = key - 1; j >= 0 ; j--)
        for (int i = 0; i < stroki; i++) {
            t[k] = tabl[i][j];
            k++;
        }

    for (int i = 0; i < stroki; i++)
        delete[] tabl[i];
    delete[] tabl;

    return t;
}

string code::transcript(const string& text, const string& open_text) {
    if (text.empty() || open_text.empty()) {
        throw cipher_error("Один из текстов пуст!");
    }

    for (char c : text) {
        if (!isalpha(c)) {
            throw cipher_error("Некорректные символы в зашифрованном тексте!");
        }
    }

    for (char c : open_text) {
        if (!isalpha(c)) {
            throw cipher_error("Некорректные символы в открытом тексте!");
        }
    }

    string t = getValidCipherText(text, open_text);
    int k = 0;
    int simvoli = t.size();
    int stroki = simvoli / key;
    char** tabl = new char* [stroki];
    for (int i = 0; i < stroki; i++)
        tabl[i] = new char [key];

    for (int j = key - 1; j >= 0 ; j--)
        for (int i = 0; i < stroki; i++) {
            tabl[i][j] = t[k];
            k++;
        }

    k = 0;
    for (int i = 0; i < stroki; i++)
        for (int j = 0; j < key; j++) {
            t[k] = tabl[i][j];
            k++;
        }

    for (int i = 0; i < stroki; i++)
        delete[] tabl[i];
    delete[] tabl;

    return t;
}

inline string code::getValidCipherText(const string& s, const string& open_text) {
    int r1 = s.size();
    int r2 = open_text.size();
    if (r1 != r2) {
        throw cipher_error("Неправильный зашифрованный текст: " + s);
    }
    return s;
}

inline string code::getValidOpenText(const string& s) {
    string text = s;

    if (text.empty()) {
        throw cipher_error("Отсутствует открытый текст!");
    }

    text.erase(remove_if(text.begin(), text.end(), [](char c) {
        if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != ' ') {
            throw cipher_error("В тексте встречены некорректные символы!");
        }
        return c == ' ';
    }), text.end());

    return text;
}

inline int code::getValidKey(int key, const string& Text) {
    if (key < 2 || key > Text.length()) {
        throw cipher_error("Ключ некорректного размера");
    }
    return key;
}