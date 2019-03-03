#ifndef CDIALOG_MAIN_H
#define CDIALOG_MAIN_H

#include "stdafx.h"
#include "thread.h"

#define ETH_TYPE_ARP        htons(0x0806)
#define ETH_TYPE_IP         htons(0x0800)

#define ARP_HW_TYPE_ETH     htons(0x0001)
#define ARP_PROTO_TYPE_IP   htons(0x0800)

#define ARP_TYPE_REQUEST    htons(1)
#define ARP_TYPE_RESPONSE   htons(2)

//коды протоколов
#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_IP_IP   4
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_UDP     17

//тип пакета
#define ICMP_TYPE_ECHO_RQ    8
#define ICMP_TYPE_ECHO_RPLY  0

//ethernet-кадр
struct SEthFrame
{ 
 unsigned char to_addr[6];//mac-адрес получателя
 unsigned char from_addr[6];//mac-адрес отправителя
 unsigned short type;//протокол
};

// ARP-пакет
struct SARPPackage 
{
 unsigned short hw_type;//протокол канального уровня (Ethernet)
 unsigned short proto_type;//протокол сетевого уровня (IP)
 unsigned char hw_addr_len;//длина MAC-адреса =6
 unsigned char proto_addr_len;//длина IP-адреса =4
 unsigned short type;//тип сообщения (запрос/ответ)
 unsigned char mac_addr_from[6];//MAC-адрес отправителя
 unsigned long ip_addr_from;//IP-адрес отправителя
 unsigned char mac_addr_to[6];//MAC-адрес получателя, нули если неизвестен
 unsigned long ip_addr_to;//IP-адрес получателя
};

//IP-пакет
struct SIPPackage
{
 unsigned char ver_head_len;//версия и длина заголовка =0x45
 unsigned char tos;//тип сервиса
 unsigned short total_len; //длина всего пакета
 unsigned short fragment_id; //идентификатор фрагмента
 unsigned short flags_framgent_offset; //смещение фрагмента
 unsigned char ttl;//TTL
 unsigned char protocol;//код протокола
 unsigned short cksum;//контрольная сумма заголовка
 unsigned long from_addr;//IP-адрес отправителя
 unsigned long to_addr;//IP-адрес получателя
};

//ICMP echo-пакет
struct SICNOEchoPackage
{
 unsigned char type;//тип
 unsigned char code;//подтип
 unsigned short cksum;//контрольная сумма
 unsigned short id;//идентификатор
 unsigned short seq;//номер пакета
};

//UDP-пакет
struct SUDPPackage
{
 unsigned short from_port;//порт отправителя
 unsigned short to_port;//порт получателя
 unsigned short len;//размер пакета
 unsigned short cksum;//контрольная сумма
};

class CDialog_Main:public CDialog
{
 protected:
  //-Переменные класса-------------------------------------------------------
  CWinThread *cWinThread_Thread;//поток
  SOCKET socket_main;//сокет
  bool Enabled;//разрешена ли работа сниффера
  vector<SPackage> vector_SPackage_Local;//принятые данные пакетов
  //-Функции класса----------------------------------------------------------
  //-Прочее------------------------------------------------------------------
 public:
  //-Конструктор класса------------------------------------------------------
  CDialog_Main(LPCTSTR lpszTemplateName,CWnd* pParentWnd);
  //-Деструктор класса-------------------------------------------------------
  ~CDialog_Main();
  //-Переменные класса-------------------------------------------------------
  //-Замещённые функции предка-----------------------------------------------
  afx_msg void OnOK(void);
  afx_msg void OnCancel(void);
  afx_msg void OnClose(void);
  afx_msg void OnDestroy(void);
  afx_msg BOOL OnInitDialog(void);
  afx_msg void OnTimer(UINT nIDEvent);
  //-Новые функции класса----------------------------------------------------
  //-Функции обработки сообщений класса--------------------------------------
  DECLARE_MESSAGE_MAP()
  afx_msg void OnCommand_Button_StartStop(void);//запуск/останов сниффера
  afx_msg void OnCommand_Button_Clear(void);//очистка списков и файлов
  afx_msg void OnCommand_Button_Save(void);//запись в файл выбранного фрагмента
  afx_msg void OnList_ItemSelectChange(void);//изменился выбранный элемент списка
  //-Новые функции класса----------------------------------------------------
 protected:
  void ThreadStop(void);//завершение потока
  //-Прочее------------------------------------------------------------------
  unsigned short GetCheckSumm(unsigned long sum,unsigned char *buf,unsigned long len);//рассчёт контрольной суммы
  void PackageDecoder(SPackage &sPackage,FILE *file,CListBox *cListBox_Ptr);//расшифровка пакетов
  void AddStringToUnit(char *string,FILE *file,CListBox *cListBox_Ptr);//добавление строки в файл и список

};

#endif