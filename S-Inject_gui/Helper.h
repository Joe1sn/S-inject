#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
using namespace std;

void banner();
void menu();
void set_color(unsigned short forecolor = 4, unsigned short backcolor = 0);
void set_normal();
string Base64Decode(string EncodedStr);