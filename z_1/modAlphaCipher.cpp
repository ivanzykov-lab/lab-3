#include "modAlphaCipher.h"
#include <locale>
#include <codecvt>
#include <iostream>

std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;

modAlphaCipher::modAlphaCipher(const std::string& skey) {
    for (unsigned i=0; i < numAlpha.size(); i++)
        alphaNum[numAlpha[i]]=i;
    key = convert(getValidKey(skey));
    
    if (key.size() > 1) {
        bool allSame = true;
        for (size_t i = 1; i < key.size(); i++) {
            if (key[i] != key[0]) {
                allSame = false;
                break;
            }
        }
        if (allSame)
            throw cipher_error("WeakKey");
    }
}

std::string modAlphaCipher::encrypt(const std::string& open_text) {
    std::vector<int> work = convert(getValidOpenText(open_text));
    for(unsigned i=0; i < work.size(); i++)
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    return convert(work);
}

std::string modAlphaCipher::decrypt(const std::string& cipher_text) {
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i=0; i < work.size(); i++)
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    return convert(work);
}

std::vector<int> modAlphaCipher::convert(const std::string& s) {
    std::wstring ws = codec.from_bytes(s);
    std::vector<int> result;
    for(auto c:ws)
        result.push_back(alphaNum[c]);
    return result;
}

std::string modAlphaCipher::convert(const std::vector<int>& v) {
    std::wstring ws;
    for(auto i:v)
        ws.push_back(numAlpha[i]);
    std::string result = codec.to_bytes(ws);
    return result;
}

std::string modAlphaCipher::getValidKey(const std::string & s) {
    std::wstring ws = codec.from_bytes(s);
    if (ws.empty())
        throw cipher_error("Пустой ключ");
    
    std::wstring tmp = ws;
    for (auto& c : tmp) {
        if(c < L'А' || c > L'я')
            throw cipher_error("Неверный ключ: содержит не-буквенные символы");
        if (c >= L'а' && c <= L'я')
            c -= 32;
    }
    
    std::string mp = codec.to_bytes(tmp);
    return mp;
}

std::string modAlphaCipher::getValidOpenText(const std::string & s) {
    std::wstring ws = codec.from_bytes(s);
    std::wstring tmp;
    
    for (auto c:ws) {
        if (c >= L'А' && c <= L'я') {
            if (c >= L'а' && c <= L'я')
                tmp.push_back(c - 32);
            else
                tmp.push_back(c);
        }
    }
    
    if (tmp.empty())
        throw cipher_error("Отсутствует открытый текст!"); 
    
    std::string mp = codec.to_bytes(tmp);
    return mp;
}

std::string modAlphaCipher::getValidCipherText(const std::string & s) {
    std::wstring ws = codec.from_bytes(s);
    
    if (ws.empty())
        throw cipher_error("Empty cipher text");
    
    for (auto c:ws) {
        if ((c < L'А' || c > L'Я') && c != L'Ё')
            throw cipher_error("Неправильный зашифрованный текст!");
    }
    
    std::string mp = codec.to_bytes(ws);
    return mp;
}