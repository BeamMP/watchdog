//
// Created by Anonymous275 on 9/9/2021.
//

#pragma once
#include <cstdint>
#include <string>
extern void watchdog_init(const std::string& crashFile, const char* SpecificPDBLocation, bool Symbols = true);
extern void generate_crash_report(uint32_t Code, size_t Address);
std::string getFunctionDetails(size_t Address);
extern void watchdog_setOffset(int64_t Off);
std::string getCrashLocation(size_t Address);
void InitSym(const char* PDBLocation);