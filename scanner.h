#ifndef SCANNER_H
#define SCANNER_H

#include <windows.h>
#include "edr.h"

void X01ScanDirectory(const WCHAR *path);
void X01ReportFile(const char *module, const char *action, const WCHAR *path,
                   const X01Verdict *v, BOOL print);

#endif
