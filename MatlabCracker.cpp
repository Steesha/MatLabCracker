#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
constexpr auto MAX_KEY_LENGTH = 255;
constexpr auto MAX_VALUE_NAME = 16383;
TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
DWORD    cbName;                   // size of name string 
TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 

struct MatLabVer
{
	std::wstring version;
	std::wstring path;
	BOOL crackActive;
	MatLabVer(std::wstring version, std::wstring path)
	{
		this->version = version;
		this->path = path;
	}

	//设置是否已经为破解版
	void SetCrackActive(BOOL crackActive)
	{
		this->crackActive = crackActive;
	}
};

std::vector<MatLabVer*> matlabs;

//ret means
//0: Not Cracked
//1: Cracked
//2: FileErr
//3: CrackErr
INT checkFileCrackActive(std::wstring dllFile, BOOL crack = false)
{
	HANDLE fHandle = CreateFile(dllFile.c_str(), GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (fHandle == INVALID_HANDLE_VALUE)
	{
		return 2;
	}
	auto bufSize = GetFileSize(fHandle, 0);
	DWORD bytesRead;
	//20Mb Buffer
	PBYTE dllBuffer = (PBYTE)malloc(bufSize);
	if (dllBuffer == NULL)
	{
		return 2;
	}
	memset(dllBuffer, 0, bufSize);
	BOOL ret = ReadFile(fHandle, dllBuffer, bufSize, &bytesRead, 0);
	if (ret == false)
	{
		CloseHandle(fHandle);
		free(dllBuffer);
		return 2;
	}
	if (bytesRead == 0)
	{
		CloseHandle(fHandle);
		free(dllBuffer);
		return 2;
	}

	PBYTE record = 0;
	//定位文件内特殊字节
	for (PBYTE iter = dllBuffer; iter < (dllBuffer + bufSize); iter++)
	{
		//实际上远小于
		if (iter < (dllBuffer + bufSize) - 100)
		{
			if (*(iter + 0) == 0x41 &&
				*(iter + 1) == 0x55 &&
				*(iter + 2) == 0x48 &&
				*(iter + 3) == 0x81 &&
				*(iter + 4) == 0xEC &&
				*(iter + 5) == 0x58 &&
				*(iter + 6) == 0x01 &&
				*(iter + 7) == 0x00 &&
				*(iter + 8) == 0x00 &&
				*(iter + 9) == 0x48)
			{
				//Found
				if (record != 0)
				{
					//发现两个相同位点，错误
					free(dllBuffer);
					CloseHandle(fHandle);
					return 2;
				}
				record = iter - 4;
			}
		}
	}

	if (record == 0)
	{
		//没有发现位点，错误
		free(dllBuffer);
		return 2;
	}

	//发现有且只有一个位点，正确，读取位点
	//原版是 0x40 0x55 0x56
	//破解版是0x33 0xC0 0xC3 (xor eax,eax \ ret)
	if (*record == 0x40 && *(record + 1) == 0x55 && *(record + 2) == 0x56)
	{
		//未破解版本
		if (crack)
		{
			//开始破解
			*record = 0x33;
			*(record + 1) = 0xC0;
			*(record + 2) = 0xC3;
			DWORD written = 0;
			BOOL ret = WriteFile(fHandle, dllBuffer, bufSize, &written, 0);
			if(ret)
			{
				return 2;
			}
			return 1;
		}

		free(dllBuffer);
		CloseHandle(fHandle);
		return 0;
	}

	if (*record == 0x33 && *(record + 1) == 0xC0 && *(record + 2) == 0xC3)
	{
		//已破解版本
		free(dllBuffer);
		CloseHandle(fHandle);
		return 1;
	}

	//不是正常文件，或者文件已经被修改
	free(dllBuffer);
	CloseHandle(fHandle);
	return 3;
}


int main()
{
	std::cout << "欢迎来到MatLab Cracker" << std::endl;
	std::cout << ">>请保证您是以管理员模式启动的，否则可能会出现一大堆难以预料的问题" << std::endl;
	std::cout << ">>Program By : https:////t.me//h0matic" << std::endl << std::endl;
	HKEY hKey;
	if (ERROR_SUCCESS !=
		RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\MathWorks"), 0, KEY_READ, &hKey))
	{
		std::cout << "注册表打开失败，请检查您是否正确安装了MatLab" << std::endl;
		system("pause");
		return -1;
	}
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD retCode;

	DWORD cchValue = MAX_VALUE_NAME;
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		0,            // longest subkey size 
		0,            // longest class string 
		0,                // number of values for this key 
		0,            // longest value name 
		0,         // longest value data 
		0,   // security descriptor 
		0);       // last write time 
	if (cSubKeys)
	{
		for (DWORD i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				std::wstring keyName = achKey;
				if (keyName.length() != 0 && keyName[0] == L'R')
				{
					//发现有效MatLab注册表项
					std::wstring regName = L"SOFTWARE\\MathWorks\\" + keyName + L"\\MATLAB";
					HKEY hKeyTest;
					if (ERROR_SUCCESS !=
						RegOpenKeyEx(HKEY_LOCAL_MACHINE, regName.c_str(), 0, KEY_READ, &hKeyTest))
					{
						//无效版本
						continue;
					}
					else
					{
						//读取目录
						DWORD cbData = 256;
						WCHAR* retData = (WCHAR*)malloc(cbData);
						if (retData == NULL)
						{
							std::cout << "严重错误，请重启程序" << std::endl;
							system("pause");
							return -1;
						}
						memset(retData, 0, cbData);
						LSTATUS ret = RegQueryValueExW(hKeyTest, NULL, NULL, NULL, (PBYTE)retData, &cbData);
						if (ERROR_SUCCESS != ret)
						{
							free(retData);
							RegCloseKey(hKeyTest);
							continue;
						}
						//检测目录
						std::wstring checkDir = (std::wstring)retData;
						checkDir += L"\\matlab_startup_plugins\\lmgrimpl";
						WIN32_FIND_DATA wdata;
						HANDLE hFind = FindFirstFile(checkDir.c_str(), &wdata);
						BOOL bFilter = (FALSE == FILE_ATTRIBUTE_DIRECTORY) ?
							TRUE : wdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
						BOOL exists = ((hFind != INVALID_HANDLE_VALUE) && bFilter) ? TRUE : FALSE;
						FindClose(hFind);
						if (exists)
						{
							//目录存在，MatLab版本有效
							MatLabVer* mlv = new MatLabVer(keyName, checkDir);
							matlabs.push_back(mlv);
						}
						free(retData);
						RegCloseKey(hKeyTest);
					}
				}
			}
		}
	}
	else
	{
		RegCloseKey(hKey);
		std::cout << "注册表打开失败，请检查您是否正确安装了MatLab" << std::endl;
		system("pause");
		return -1;
	}

	//checkCrackActive
	for (auto i = matlabs.begin(); i != matlabs.end();)
	{
		std::wstring dllFile = (*i)->path + L"\\libmwlmgrimpl.dll";
		INT ret = checkFileCrackActive(dllFile);
		if (ret == 2)
		{
			//释放
			delete (*i);
			matlabs.erase(i);
			i = matlabs.begin(); //由于擦除vector，让vector从头遍历
			continue;
		}
		if (ret == 3)
		{
			std::wcout << L"[MatLab - " <<
				(*i)->version << L"]";
			std::cout << "此版本已被修改，可能是MatLab更新，请注意" << std::endl;
			//释放
			delete (*i);
			matlabs.erase(i);
			i = matlabs.begin(); //由于擦除vector，让vector从头遍历
			continue;
		}
		else
		{
			(*i)->SetCrackActive(ret == 1 ? TRUE : FALSE);
			std::wcout << L"[MatLab - " <<
				(*i)->version << L"] CrackStatus:" <<
				((*i)->crackActive ? L"Cracked" : L"Not-Cracked") << std::endl;
		}
		i++;
	}

	if (matlabs.size() == 0)
	{
		RegCloseKey(hKey);
		std::cout << "未找到可用的MatLab版本，请检查您是否正确安装了MatLab" << std::endl;
		system("pause");
		return -1;
	}

	
	//破解
	for (auto i = matlabs.begin(); i != matlabs.end(); i++)
	{

		if (!(*i)->crackActive)
		{
			std::cout << std::endl << std::endl;
			std::cout << "[Crack]当前您操作的是版本[";
			std::wcout << (*i)->version << "]" << std::endl;
			std::cout << "输入[Y]开始破解本版本，输入其他的跳过" << std::endl;
			std::string inputs;
			std::cin >> inputs;
			if (inputs == "Y")
			{
				if (checkFileCrackActive((*i)->path, true) == 1)
				{
					std::cout << "本版本破解完毕,请配合License一起使用" << std::endl;
				}
				else
				{
					std::cout << "破解失败，请查看你是否以管理员模式启动" << std::endl;
				}
			}
		}
		else
		{
			std::cout << "[Crack]版本[";
				std::wcout << (*i)->version << "]";
				std::cout << "不需要被破解" << std::endl;
		}
		
	}
	

	//释放MatlabVer类
	for (auto i = matlabs.begin(); i != matlabs.end(); i++)
	{
		delete (*i);
	}

	std::cout << "感谢您使用本软件" << std::endl;
	system("pause");
	RegCloseKey(hKey);
	return 0;
}
