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

//���� ����������
#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_IP_IP   4
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_UDP     17

//��� ������
#define ICMP_TYPE_ECHO_RQ    8
#define ICMP_TYPE_ECHO_RPLY  0

//ethernet-����
struct SEthFrame
{ 
 unsigned char to_addr[6];//mac-����� ����������
 unsigned char from_addr[6];//mac-����� �����������
 unsigned short type;//��������
};

// ARP-�����
struct SARPPackage 
{
 unsigned short hw_type;//�������� ���������� ������ (Ethernet)
 unsigned short proto_type;//�������� �������� ������ (IP)
 unsigned char hw_addr_len;//����� MAC-������ =6
 unsigned char proto_addr_len;//����� IP-������ =4
 unsigned short type;//��� ��������� (������/�����)
 unsigned char mac_addr_from[6];//MAC-����� �����������
 unsigned long ip_addr_from;//IP-����� �����������
 unsigned char mac_addr_to[6];//MAC-����� ����������, ���� ���� ����������
 unsigned long ip_addr_to;//IP-����� ����������
};

//IP-�����
struct SIPPackage
{
 unsigned char ver_head_len;//������ � ����� ��������� =0x45
 unsigned char tos;//��� �������
 unsigned short total_len; //����� ����� ������
 unsigned short fragment_id; //������������� ���������
 unsigned short flags_framgent_offset; //�������� ���������
 unsigned char ttl;//TTL
 unsigned char protocol;//��� ���������
 unsigned short cksum;//����������� ����� ���������
 unsigned long from_addr;//IP-����� �����������
 unsigned long to_addr;//IP-����� ����������
};

//ICMP echo-�����
struct SICNOEchoPackage
{
 unsigned char type;//���
 unsigned char code;//������
 unsigned short cksum;//����������� �����
 unsigned short id;//�������������
 unsigned short seq;//����� ������
};

//UDP-�����
struct SUDPPackage
{
 unsigned short from_port;//���� �����������
 unsigned short to_port;//���� ����������
 unsigned short len;//������ ������
 unsigned short cksum;//����������� �����
};

class CDialog_Main:public CDialog
{
 protected:
  //-���������� ������-------------------------------------------------------
  CWinThread *cWinThread_Thread;//�����
  SOCKET socket_main;//�����
  bool Enabled;//��������� �� ������ ��������
  vector<SPackage> vector_SPackage_Local;//�������� ������ �������
  //-������� ������----------------------------------------------------------
  //-������------------------------------------------------------------------
 public:
  //-����������� ������------------------------------------------------------
  CDialog_Main(LPCTSTR lpszTemplateName,CWnd* pParentWnd);
  //-���������� ������-------------------------------------------------------
  ~CDialog_Main();
  //-���������� ������-------------------------------------------------------
  //-���������� ������� ������-----------------------------------------------
  afx_msg void OnOK(void);
  afx_msg void OnCancel(void);
  afx_msg void OnClose(void);
  afx_msg void OnDestroy(void);
  afx_msg BOOL OnInitDialog(void);
  afx_msg void OnTimer(UINT nIDEvent);
  //-����� ������� ������----------------------------------------------------
  //-������� ��������� ��������� ������--------------------------------------
  DECLARE_MESSAGE_MAP()
  afx_msg void OnCommand_Button_StartStop(void);//������/������� ��������
  afx_msg void OnCommand_Button_Clear(void);//������� ������� � ������
  afx_msg void OnCommand_Button_Save(void);//������ � ���� ���������� ���������
  afx_msg void OnList_ItemSelectChange(void);//��������� ��������� ������� ������
  //-����� ������� ������----------------------------------------------------
 protected:
  void ThreadStop(void);//���������� ������
  //-������------------------------------------------------------------------
  unsigned short GetCheckSumm(unsigned long sum,unsigned char *buf,unsigned long len);//������� ����������� �����
  void PackageDecoder(SPackage &sPackage,FILE *file,CListBox *cListBox_Ptr);//����������� �������
  void AddStringToUnit(char *string,FILE *file,CListBox *cListBox_Ptr);//���������� ������ � ���� � ������

};

#endif