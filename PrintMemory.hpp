#pragma once
#include <stddef.h>
#include <stdint.h>
#include <tchar.h>
#include <windows.h>

void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept;
void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept;

