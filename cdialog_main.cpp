#include "cdialog_main.h"

extern CEvent cEvent_ThreadExit;
extern CThread cThread;

//-Функции обработки сообщений класса----------------------------------------
BEGIN_MESSAGE_MAP(CDialog_Main,CDialog)
 ON_WM_DESTROY()
 ON_WM_CLOSE()
 ON_WM_TIMER()
 ON_LBN_SELCHANGE(IDC_LIST_MAIN_TEXT_DATA,OnList_ItemSelectChange)
 ON_COMMAND(IDC_BUTTON_MAIN_START_STOP,OnCommand_Button_StartStop)
 ON_COMMAND(IDC_BUTTON_MAIN_CLEAR,OnCommand_Button_Clear)
 ON_COMMAND(IDC_BUTTON_MAIN_SAVE_HEX,OnCommand_Button_Save)
END_MESSAGE_MAP()
//-Конструктор класса--------------------------------------------------------
CDialog_Main::CDialog_Main(LPCTSTR lpszTemplateName, CWnd* pParentWnd):CDialog(lpszTemplateName,pParentWnd)
{
 cWinThread_Thread=NULL;
 socket_main=INVALID_SOCKET;
 Enabled=false;
}
//-Деструктор класса---------------------------------------------------------
CDialog_Main::~CDialog_Main()
{
 ThreadStop();
 long size=vector_SPackage_Local.size();
 for(long n=0;n<size;n++) delete[](vector_SPackage_Local[n].Data);
 vector_SPackage_Local.clear();
}
//-Замещённые функции предка-------------------------------------------------
afx_msg void CDialog_Main::OnOK(void)
{
}
afx_msg void CDialog_Main::OnCancel(void)
{
}
afx_msg void CDialog_Main::OnClose(void)
{
 EndDialog(0);
}
afx_msg BOOL CDialog_Main::OnInitDialog(void)
{
 //настроим сокеты
 WSADATA wsadata;
 int error=WSAStartup(0x0202,&wsadata);
 if (error!=0) 
 {
  MessageBox("Ошибка инициализации сокетов","Ошибка",MB_OK);
  EndDialog(0);
  return(0);
 }
 if (wsadata.wVersion!=0x0202)
 {
  MessageBox("Неверная версия библиотеки сокетов","Ошибка",MB_OK);
  EndDialog(0);
  return(0);
 }
 socket_main=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
 if (socket_main==INVALID_SOCKET)
 {
  MessageBox("Ошибка открытия сокета!","Ошибка",MB_OK);
  EndDialog(0);
  return(0);
 }
 char name[255];
 HOSTENT* phe;
 SOCKADDR_IN sa;
 gethostname(name,sizeof(name));
 phe=gethostbyname(name);
 if (phe==NULL)
 {
  MessageBox("Ошибка получения параметров хоста!","Ошибка",MB_OK);
  closesocket(socket_main);
  socket_main=INVALID_SOCKET;
  EndDialog(0);
  return(0);
 }
 ZeroMemory(&sa,sizeof(sa));
 sa.sin_family=AF_INET;
 sa.sin_addr.s_addr=((struct in_addr*)phe->h_addr_list[0])->s_addr;
 if (bind(socket_main,(SOCKADDR *)&sa,sizeof(SOCKADDR))==SOCKET_ERROR) 
 {
  MessageBox("Не могу поставить сокет на прослушивание!","Ошибка",MB_OK);
  closesocket(socket_main);
  socket_main=INVALID_SOCKET;
  EndDialog(0);
  return(0);
 }
 unsigned long flag=1;
 if (ioctlsocket(socket_main,SIO_RCVALL,&flag)!=0) 
 {
  MessageBox("Не могу задать параметры сокета SIO_RCVALL!","Ошибка",MB_OK);
  closesocket(socket_main);
  socket_main=INVALID_SOCKET;
  EndDialog(0);
  return(0);
 }
 //запускаем поток
 cEvent_ThreadExit.ResetEvent();
 cWinThread_Thread=AfxBeginThread((AFX_THREADPROC)Thread,&socket_main);
 cWinThread_Thread->m_bAutoDelete=FALSE;
 //подключим таймер
 SetTimer(ID_TIMER_UPDATE,10,NULL);
 return(CDialog::OnInitDialog());
}
afx_msg void CDialog_Main::OnDestroy(void)
{
 KillTimer(ID_TIMER_UPDATE);
 ThreadStop();
 if (socket_main!=INVALID_SOCKET) closesocket(socket_main);
 WSACleanup();
 CDialog::OnDestroy();
}
//-Функции обработки сообщений класса----------------------------------------
afx_msg void CDialog_Main::OnTimer(UINT nIDEvent)
{
 if (nIDEvent==ID_TIMER_UPDATE)
 {
  cThread.Lock();
  vector<SPackage> *vector_SPackage_ptr=cThread.GetVectorSPackagePtr();
  long size=vector_SPackage_ptr->size();
  //добавляем данные на экран и в файл
  if (Enabled==true)
  {
   FILE *file_bin=fopen("sniffer_out.bin","ab");
   FILE *file_txt=fopen("sniffer_out.txt","ab");
   for(long n=0;n<size;n++)
   {
    unsigned char line[255];//добавляемая в список строка
    SPackage sPackage=(*vector_SPackage_ptr)[n];
    long length=sPackage.Size;
    //выводим заголовок пакета
	if (file_txt!=NULL)
	{
     PackageDecoder(sPackage,file_txt,NULL);
     long l=0;
     while(l<length)
	 {
      long s=50;
      if (l+s>length) s=length-l;
      long line_length=0;
      for(long m=0;m<s;m++,l++) 
	  {
       unsigned long code=sPackage.Data[l];
       unsigned char h=(code>>4)&0x0F;
       unsigned char l=code&0x0F;
	   char text[3];
	   if (h<=9) text[0]=h+'0';
	        else text[0]=h-10+'A';	   
	   if (l<=9) text[1]=l+'0';
	        else text[1]=l-10+'A';
	   text[2]=0;
	   fprintf(file_txt,"%s ",text);
	  }
	  fprintf(file_txt,"\r\n");
	 }
	 fprintf(file_txt,"\r\n");
	}
    sPackage.Index=((CListBox*)GetDlgItem(IDC_LIST_MAIN_TEXT_DATA))->GetCount();//номер строки, с которой начинается пакет
	if (file_bin!=NULL) fwrite(sPackage.Data,length,sizeof(unsigned char),file_bin);
	long l=0;
	while(l<length)
	{
     long s=50;
	 if (l+s>length) s=length-l;
     for(long m=0;m<s;m++,l++) 
     {
      unsigned char symbol=sPackage.Data[l];
      if (symbol<32) symbol='.';
	  line[m]=symbol;
     }
	 line[s]=0;
     ((CListBox*)GetDlgItem(IDC_LIST_MAIN_TEXT_DATA))->AddString((char*)line);
	}    
	((CListBox*)GetDlgItem(IDC_LIST_MAIN_TEXT_DATA))->AddString("");
    vector_SPackage_Local.push_back(sPackage);
   }
   if (file_bin!=NULL) fclose(file_bin);
   if (file_txt!=NULL) fclose(file_txt);
  }
  else
  {
   for(long n=0;n<size;n++) delete[]((*vector_SPackage_ptr)[n].Data);
  }
  vector_SPackage_ptr->clear();
  cThread.Unlock();
 }
 CDialog::OnTimer(nIDEvent);
}
//запуск/останов сниффера
afx_msg void CDialog_Main::OnCommand_Button_StartStop(void)
{
 if (Enabled==true)
 {
  ((CButton*)GetDlgItem(IDC_BUTTON_START_STOP))->SetWindowText("Запустить");
  Enabled=false;
 }
 else
 {
  ((CButton*)GetDlgItem(IDC_BUTTON_START_STOP))->SetWindowText("Остановить"); 
  Enabled=true;
 }
}
//изменился выбранный элемент списка
afx_msg void CDialog_Main::OnList_ItemSelectChange(void)
{
 long line=((CListBox*)GetDlgItem(IDC_LIST_MAIN_TEXT_DATA))->GetCurSel();
 if (line!=LB_ERR)
 {
  //заполняем список
  ((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->ResetContent();  
  //ищем пакет в списке
  long size=vector_SPackage_Local.size();
  long package_index=0;
  while(package_index<size)
  {
   SPackage sPackage=vector_SPackage_Local[package_index];
   if (sPackage.Index>line)
   {
    package_index--;
    break;
   }
   package_index++;
  }
  if (package_index>=size) package_index=size-1;
  if (package_index<0) package_index=0;
  //зная индекс пакета, выводим его
  SPackage sPackage=vector_SPackage_Local[package_index];
  long length=sPackage.Size;
  PackageDecoder(sPackage,NULL,((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))); 
  ((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->AddString("");

  long l=0;
  char line[255];
  while(l<length)
  {
   long s=20;
   if (l+s>length) s=length-l;
   long line_length=0;
   for(long m=0;m<s;m++,l++) 
   {
    unsigned long code=sPackage.Data[l];
    unsigned char h=(code>>4)&0x0F;
    unsigned char l=code&0x0F;
	if (h<=9) line[line_length]=h+'0';
	     else line[line_length]=h-10+'A';
	line_length++;
	if (l<=9) line[line_length]=l+'0';
	     else line[line_length]=l-10+'A';
	line_length++;
    line[line_length]=' ';line_length++;    
   }
   line[line_length]=0;
   ((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->AddString((char*)line);
  }
 }
}
//очистка списков и файлов
afx_msg void CDialog_Main::OnCommand_Button_Clear(void)
{
 FILE *file=fopen("sniffer_out.bin","wb");
 if (file!=NULL) fclose(file);
 file=fopen("sniffer_out.txt","wb");
 if (file!=NULL) fclose(file);
 ((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->ResetContent();
 ((CListBox*)GetDlgItem(IDC_LIST_MAIN_TEXT_DATA))->ResetContent();
 long size=vector_SPackage_Local.size();
 for(long n=0;n<size;n++) delete[](vector_SPackage_Local[n].Data);
 vector_SPackage_Local.clear();
}
//запись в файл выбранного фрагмента
afx_msg void CDialog_Main::OnCommand_Button_Save(void)
{
 long count=((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->GetCount();
 FILE *file=fopen("save_data.txt","ab");
 if (file==NULL) return;
 for(long n=0;n<count;n++)
 {
  char string[255];
  ((CListBox*)GetDlgItem(IDC_LIST_MAIN_HEX_DATA))->GetText(n,string);
  fprintf(file,"%s\r\n",string);
 }
 fprintf(file,"----------------------------------------------------------------------------------------------------\r\n");
 fclose(file);
}
//-Новые функции класса------------------------------------------------------
void CDialog_Main::ThreadStop(void)
{
 //отключим поток подключения
 if (cWinThread_Thread!=NULL)
 {
  cEvent_ThreadExit.SetEvent();
  WaitForSingleObject(cWinThread_Thread->m_hThread,INFINITE);
  delete(cWinThread_Thread);
  cWinThread_Thread=NULL;
 }
}
//-Прочее--------------------------------------------------------------------
unsigned short CDialog_Main::GetCheckSumm(unsigned long sum,unsigned char *buf,unsigned long len)
{
 //Рассчитываем сумму word'ов блока (big endian)
 //(блок выравнивается на word нулём)
 while(len>=2)
 {
  unsigned short code=buf[0];
  code<<=8;
  code|=buf[1];
  sum+=code;
  buf+=2;
  len-=2;
 }
 if (len) sum+=(static_cast<unsigned short>(buf[0]))<<8;
 //складываем старший и младший word суммы пока не получим число, влезающее в word
 while (sum>>16) sum=(sum&0xFFFF)+(sum>>16);
 //Снова конвертируем в big endian и берём дополнение
  return(0xFFFF^htons(static_cast<unsigned short>(sum)));
}
//расшифровка пакетов
void CDialog_Main::PackageDecoder(SPackage &sPackage,FILE *file,CListBox *cListBox_Ptr)
{
 //сниффер получает всегда IP пакет
 long length=sPackage.Size;
 //выводим заголовок пакета
 if (length>=sizeof(SIPPackage))
 {
  char string[255];
  SIPPackage* sIPPackagePtr=reinterpret_cast<SIPPackage *>(sPackage.Data);   
  if (sIPPackagePtr->ver_head_len==0x45)
  {
   char s_protocol[255];
   sprintf(s_protocol,"неизвестный");
   if (sIPPackagePtr->protocol==IP_PROTOCOL_UDP) sprintf(s_protocol,"UDP");
   if (sIPPackagePtr->protocol==IP_PROTOCOL_ICMP) sprintf(s_protocol,"ICMP");
   if (sIPPackagePtr->protocol==IP_PROTOCOL_TCP) sprintf(s_protocol,"TCP");
   if (sIPPackagePtr->protocol==IP_PROTOCOL_IP_IP) sprintf(s_protocol,"IP внутри IP");
   sprintf(string,"Протокол: %d (%s)",sIPPackagePtr->protocol,s_protocol);
   AddStringToUnit(string,file,cListBox_Ptr);
   sprintf(string,"Полная длина IP пакета: %d",htons(sIPPackagePtr->total_len));
   AddStringToUnit(string,file,cListBox_Ptr);
   unsigned char *ptr;
   ptr=reinterpret_cast<unsigned char*>(&sIPPackagePtr->from_addr);
   sprintf(string,"Отправитель: %.8X [%i.%i.%i.%i]",sIPPackagePtr->from_addr,ptr[0],ptr[1],ptr[2],ptr[3]);
   AddStringToUnit(string,file,cListBox_Ptr);
   ptr=reinterpret_cast<unsigned char*>(&sIPPackagePtr->to_addr);
   sprintf(string,"Получатель: %.8X [%i.%i.%i.%i]",sIPPackagePtr->to_addr,ptr[0],ptr[1],ptr[2],ptr[3]);
   AddStringToUnit(string,file,cListBox_Ptr);
   //проверяем контрольную сумму
   unsigned short checksumm_p=sIPPackagePtr->cksum;
   sIPPackagePtr->cksum=0;
   unsigned short checksumm=GetCheckSumm(0,sPackage.Data,sizeof(SIPPackage));
   sIPPackagePtr->cksum=checksumm_p;
   sprintf(string,"Контрольная сумма IP: %.4X (рассчитанная: %.4X)",sIPPackagePtr->cksum,checksumm);
   AddStringToUnit(string,file,cListBox_Ptr);
   if (checksumm_p==checksumm) AddStringToUnit("Контрольная сумма IP верная",file,cListBox_Ptr);
                          else AddStringToUnit("Ошибка контрольной суммы IP!",file,cListBox_Ptr);
   //расшифровываем пакет, если это возможно						   
   if (sIPPackagePtr->protocol==IP_PROTOCOL_UDP && length>=sizeof(SIPPackage)+sizeof(SUDPPackage))
   {
    SUDPPackage *sUDPPackagePtr=reinterpret_cast<SUDPPackage *>(sPackage.Data+sizeof(SIPPackage));
    sprintf(string,"Порт отправителя: %d",htons(sUDPPackagePtr->from_port));
    AddStringToUnit(string,file,cListBox_Ptr);
    sprintf(string,"Порт получателя: %d",htons(sUDPPackagePtr->to_port));
    AddStringToUnit(string,file,cListBox_Ptr);
    sprintf(string,"Длина UDP пакета: %d",htons(sUDPPackagePtr->len));
    AddStringToUnit(string,file,cListBox_Ptr);    	
    //проверяем контрольную сумму UDP (она считается от псевдозаголовка)
    unsigned short checksumm_p=sUDPPackagePtr->cksum;
    sUDPPackagePtr->cksum=0;
	unsigned short checksumm=htons(sUDPPackagePtr->len)+IP_PROTOCOL_UDP;
    checksumm=GetCheckSumm(checksumm,sPackage.Data+sizeof(SIPPackage)-8,htons(sUDPPackagePtr->len)+8);
	sUDPPackagePtr->cksum=checksumm_p;
    sprintf(string,"Контрольная сумма UDP: %.4X (рассчитанная: %.4X)",sUDPPackagePtr->cksum,checksumm);
    AddStringToUnit(string,file,cListBox_Ptr);
    if (checksumm_p==checksumm) AddStringToUnit("Контрольная сумма UDP верная",file,cListBox_Ptr);
                          else AddStringToUnit("Ошибка контрольной суммы UDP!",file,cListBox_Ptr);
   }
  }
 }
}
//добавление строки в файл и список
void CDialog_Main::AddStringToUnit(char *string,FILE *file,CListBox *cListBox_Ptr)
{
 if (file!=NULL) fprintf(file,"%s\r\n",string);
 if (cListBox_Ptr!=NULL) cListBox_Ptr->AddString(string);
}
