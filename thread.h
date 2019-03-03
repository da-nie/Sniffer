#ifndef THREAD_H
#define THREAD_H

#include "stdafx.h"

UINT Thread(LPVOID pParam);//поток

struct SPackage
{
 unsigned long Size;//размер пакета
 unsigned char *Data;//данные пакета
 unsigned long Index;//номер в списке (используется только в графическом интерфейсе)
};

class CThread
{
 protected:  
  vector<SPackage> vector_SPackage;//принятые данные
  CCriticalSection cCriticalSection;//критическая секция для доступа к принятым данным
 public:  
  //конструктор
  CThread(void);
  //деструктор
  ~CThread();
  void Processing(SOCKET socket);//запустить
  void Lock(void);//заблокировать приём данных
  void Unlock(void);//разблокировать приём данных
  vector<SPackage>* GetVectorSPackagePtr(void);//получить указатель на вектор принятых данных
 protected:
};

#endif