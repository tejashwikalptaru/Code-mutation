#define ISOLATION_AWARE_ENABLED 1
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <windows.h>
#include "resource.h"

int starts;
int xx,yy,zz;
HINSTANCE hInst;
char capt[15] = "Congratulation";
char msgs[48] = "You have successfully cracked this challenge!!!";

// original code or function bytes (61 bytes)
// original XOR value with 5 = 185
// original addition of all bytes = 7288
//unsigned char data[] = {0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x45, 0x0C, 0x8B, 0x4D, 0x08, 0x99, 0xF7, 0xF9, 0x85, 0xD2, 0x75, 0x29, 0x8B, 0x45, 0x10, 0x41, 0x99, 0xF7, 0xF9, 0x89, 0x4D, 0x08, 0x85, 0xD2, 0x75, 0x1B, 0x8B, 0x45, 0x14, 0x41, 0x99, 0xF7, 0xF9, 0x85, 0xD2, 0x75, 0x10, 0x6A, 0x40, 0xFF, 0x75, 0x18, 0xFF, 0x75, 0x1C, 0x6A, 0x00, 0x8D, 0x75, 0x20, 0x3E, 0xFF, 0x16, 0x5E, 0x5D, 0xC3};

// modified function bytes, XORed each original bytes value with 17
unsigned char data[61] = {0x44, 0x9A, 0xFD, 0x47, 0x9A, 0x54, 0x1D, 0x9A, 0x5C, 0x19, 0x88, 0xE6, 0xE8, 0x94, 0xC3, 0x64, 0x38, 0x9A, 0x54, 0x01, 0x50, 0x88, 0xE6, 0xE8, 0x98, 0x5C, 0x19, 0x94, 0xC3, 0x64, 0x0A, 0x9A, 0x54, 0x05, 0x50, 0x88, 0xE6, 0xE8, 0x94, 0xC3, 0x64, 0x01, 0x7B, 0x51, 0xEE, 0x64, 0x09, 0xEE, 0x64, 0x0D, 0x7B, 0x11, 0x9C, 0x64, 0x31, 0x2F, 0xEE, 0x07, 0x4F, 0x4C, 0xD2 };

// beginning of modifiable function
// putting here a dummy function of 71 bytes (some extra space of 10 bytes) and this will be overwritten 
// with original code upon successful verification
void selfFunction(int start, int x, int y, int z, char cap[], char msg[],int* msgb){
	__asm{
		xor eax,eax
		xor ebx,ebx
		xor ecx,ecx
		xor edx,edx
		mov eax,start
		mov ebx,x
		mov ecx,y
		mov edx,z
		mov esi, cap
		lp:
			add eax,[esi]
			xor eax,ecx
			xor eax, edx
			inc esi
			dec ecx
		loop lp
		add eax,eax
		xor eax, 0xdeadbeef
		add eax,edx
		sub eax,ecx
		inc ecx
		add ecx,eax
		xor eax,eax
		xor edx,eax
		inc edx
		dec esi
		dec esi
		dec esi
		add edx,[msg]
		xor edx,msgb
		mov eax,edx
	}
}

// function to write the new codes at given address
void enc(int dwAddress, int dwSize){
	__asm{
		mov esi, dwAddress
		mov edi, offset data
		mov ecx, dwSize
		xor eax, eax
		lp1:
			movsx al, [edi]
			mov byte ptr [esi], al 
			inc esi
			inc edi
		loop lp1
	}
}

unsigned GetLength(const unsigned n) 
{
	if(n==12345678)
		return 0;
	else{
		if (n < 10) return 1;
		return 1 + GetLength(n / 10);
	}
}

int GetSum(int num)
{
	int sum=0,r=0;
	while(num)
	{
		r=num%10;
		num=num/10;
		sum=sum+r;
	}
	return sum;
}

void Calculate(HWND hWnd)
{
	xx = 0, yy = 0, zz = 0;
	unsigned val = 5, sum = 0;

	//backup the modified data array
	unsigned char backup[62] = "";
	lstrcpy((char*)backup,(char*)data);

	int part = GetDlgItemInt(hWnd,IDC_EDIT1,NULL,false);
	if(GetLength(part) == 4)
	{
		part = GetSum(part);
		for(int i=0;i<61;i++)
		{
			data[i] = data[i] ^ part;
		}
		for(int i=0;i<61;i++)
		{
			val = val^data[i];
		}
		if(val == 185)
		{
			for(int i=0;i<61;i++)
			{
				sum = sum + data[i];
			}
			if(sum == 7288)
			{
				// if we are here means original bytes of functions in data array are restored
				// as we XORed them again with part value, which will contain 17, then only original 
				// bytes are restored and 185 and 7288 are retrieved, because they are checksum values
				// for original function bytes

				xx = GetDlgItemInt(hWnd,IDC_EDIT2,NULL,false);
				yy = GetDlgItemInt(hWnd,IDC_EDIT3,NULL,false);
				zz = GetDlgItemInt(hWnd,IDC_EDIT4,NULL,false);

				if(GetLength(xx) == 4 && GetLength(yy) == 4 && GetLength(zz) == 4)
				{
					xx = GetSum(xx);
					yy = GetSum(yy);
					zz = GetSum(zz);
					if(xx != 0 && yy!= 0 && zz != 0)
					{
						int functionSize = 61;
						DWORD dwOldProtect;
						void (*func)(int,int,int,int,char c[],char m[],int* msgb);
						func = &selfFunction;

						// We need to give ourselves access to modify data at the given address
						VirtualProtect(func, functionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	
						enc((int)func, functionSize);
	
						// Restore the old protection
						VirtualProtect(func, functionSize, dwOldProtect, NULL);

						// Test the function
						func(part,xx,yy,zz,capt,msgs,(int*)&MessageBox);
					}
				}
			}
		}
		//Restore the data
		lstrcpy((char*)data,(char*)backup);
	}
}

BOOL CALLBACK DlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		SendMessage(hWnd,WM_SETICON,1,(LPARAM)(LoadIcon(hInst,MAKEINTRESOURCE(IDI_ICON1))));
		return TRUE;
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDOK:
				Calculate(hWnd);
				break;
			}
		}
		return TRUE;
	case WM_CLOSE:
	case WM_DESTROY:
		EndDialog(hWnd,0);
		return TRUE;
	}
	return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){

	hInst = hInstance;
	DialogBoxParam(hInstance,MAKEINTRESOURCE(IDD_DIALOG1),HWND_DESKTOP,DLGPROC(&DlgProc),NULL);
	return 0;
}