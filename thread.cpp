#include "thread.h"

CEvent cEvent_ThreadExit;//требование на выход из потока
CThread cThread;//класс потока

UINT Thread(LPVOID pParam)
{
 SOCKET socket=*((SOCKET*)pParam);
 cThread.Processing(socket);
 return(0);
}
//функции класса потока
CThread::CThread(void)
{ 

}
CThread::~CThread()
{
 long size=vector_SPackage.size();
 for(long n=0;n<size;n++) delete[](vector_SPackage[n].Data);
 vector_SPackage.clear();
}
void CThread::Processing(SOCKET socket)
{ 
 unsigned char *Buffer=new unsigned char[65536];
 while(1)
 {
  if (WaitForSingleObject(cEvent_ThreadExit.m_hObject,0)==WAIT_OBJECT_0) break;
  fd_set Readen;
  FD_ZERO(&Readen);//обнул€ем список
  FD_SET(socket,&Readen);//добавл€ем сокет
  fd_set Exeption;
  FD_ZERO(&Exeption);//обнул€ем список
  FD_SET(socket,&Exeption);//добавл€ем сокет сервера
  //ждЄм событий в системе
  timeval timeout;
  timeout.tv_sec=1;
  timeout.tv_usec=0;
  //спрашиваем, не случилось ли чего с сокетами?
  if (select(0,&Readen,0,&Exeption,&timeout)>0)
  {
   if (FD_ISSET(socket,&Readen))//пришли данные дл€ чтени€ из сокета
   {
    //читаем данные
	SPackage sPackage; 
    sPackage.Size=recv(socket,(char*)Buffer,65535,0);
    sPackage.Data=new unsigned char[sPackage.Size+1];
	memcpy(sPackage.Data,Buffer,sPackage.Size);
	//добавл€ем в буфер
	cCriticalSection.Lock();
    long size=vector_SPackage.size();
	if (size<10000) vector_SPackage.push_back(sPackage);
	           else delete[](sPackage.Data);	
	cCriticalSection.Unlock();
    continue;
   }
   if (FD_ISSET(socket,&Exeption)) break;//произошЄл сбой сокета
  }
 }
 delete[](Buffer);
}
//заблокировать приЄм данных
void CThread::Lock(void)
{
 cCriticalSection.Lock();
}
//разблокировать приЄм данных
void CThread::Unlock(void)
{
 cCriticalSection.Unlock();
}
//получить указатель на вектор прин€тых данных
vector<SPackage>* CThread::GetVectorSPackagePtr(void)
{
 return(&vector_SPackage);
}
