#define VC_EXTRALEAN
#include <afxwin.h>
#include <afxdisp.h>
#include <afxext.h>
#include <afxcview.h>
#include <afxcmn.h>
#include <afxmt.h> 

#include <math.h>
#include <winsock2.h>
#include <string.h>
#include <vector>
using namespace std;

#include "resource.h"

#ifndef SIO_RCVALL
#define SIO_RCVALL 0x98000001
#endif

#define ID_TIMER_UPDATE WM_USER+1


