#ifndef THREAD_H
#define THREAD_H

#include "stdafx.h"

UINT Thread(LPVOID pParam);//�����

struct SPackage
{
 unsigned long Size;//������ ������
 unsigned char *Data;//������ ������
 unsigned long Index;//����� � ������ (������������ ������ � ����������� ����������)
};

class CThread
{
 protected:  
  vector<SPackage> vector_SPackage;//�������� ������
  CCriticalSection cCriticalSection;//����������� ������ ��� ������� � �������� ������
 public:  
  //�����������
  CThread(void);
  //����������
  ~CThread();
  void Processing(SOCKET socket);//���������
  void Lock(void);//������������� ���� ������
  void Unlock(void);//�������������� ���� ������
  vector<SPackage>* GetVectorSPackagePtr(void);//�������� ��������� �� ������ �������� ������
 protected:
};

#endif