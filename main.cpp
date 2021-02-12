#include <cstdio>
#include <iostream>
#include <stdint.h>
#include <vector>
#include <boost/crc.hpp>
#include <boost/cstdint.hpp>
#include <ctime>
#include <string>
#include <sstream>
#include <complex>
#include <csignal>
#include "hash-lib/sha256.h"
#include <fstream>
#include <random>
#include <uhd/utils/thread_priority.hpp>
#include <uhd/utils/safe_main.hpp>
#include <uhd/utils/static.hpp>
#include <uhd/usrp/multi_usrp.hpp>
#include <uhd/exception.hpp>

#define SAMPS_NUM 2175620                                  //rozmiar bufora uzywanego do transmisji


using namespace std;

int stop_signal_called = false;

void hex2bin(vector<int> hex, vector<int>& bits);                                    //przeliczanie calego pakietu z hex do bin
void crc16(vector<int>& data);                                                       //obliczanie sumy kontrolnej po wszystkich bitach pakietu
void id_gen(string word, vector<int>& data);                                         //obliczanie pola identyfukujacego
void data_gen(vector<int>& packet);                                                  //generowanie losowych danych
void choice(char& nbr);                                                              //wybor metody wielodostepu TDMA/ALOHA
void tdma_frame1_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal );    //scenariusz pierwszej komunikacji wezla 0x02 z 0x01
void tdma_frame1(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal );                                                //scenariusz komunikacji wezla 0x02 z 0x01
void tdma_frame2_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal);    //scenariusz pierwszej komunikacji wezla 0x03 z 0x01
void tdma_frame2(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal);                                                //scenariusz komunikacji wezla 0x03 z 0x01
void tdma_frame3_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal);     //scenariusz pierwszej komunikacji wezla 0x04 z 0x01
void tdma_frame3(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal);                                                //scenariusz komunikacji wezla 0x04 z 0x01
void tdma_1(vector<complex<float> >mod_sign, vector<complex<float> >&tdma);          //transmisja wezla 0x01
void tdma_2(vector<complex<float> >mod_sign, vector<complex<float> >&tdma);          //transmisja wezla 0x02
void tdma_3(vector<complex<float> >mod_sign, vector<complex<float> >& tdma);         //transmisja wezla 0x03
int rand_aloha();                                                                    //losowe odstepy w czasie miedzy pakietami
void aloha_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal);                    //realizacja dostepu wielokrotnego ALOHA
void aloha(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal);                                                                //realizacja dostepu wielokrotnego ALOHA
void aloha_collision(vector<int> br, vector<int> br2, vector<int>dat, vector<int> dat2, vector<int> ack, vector<int> ack2, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal);   //realizacja kolizji w wielodostępie ALOHA
void sig_int_handler(int);
void usrp_streaming(vector <complex <float> > &tx_signal);          //komunikacja z urządzeniem USRP 2920 NI


int main()
{
    srand(time(NULL));
    vector<int> preamb_synch{ 0xDC, 0xDC, 0xDC, 0xDC, 0xE7,0x18 };  //4B preambuly i 2B ciagu synchronizacyjnego
    vector<int> preamb{ 0xDC, 0xDC, 0xDC, 0xDC };             //preambula
    vector<int> synch{ 0xE7,0x18 };                           //ciag synchronizacyjny

    //-------------------------PAKIETY-------------------------
    //Adresy:
    //  0x01        - master
    //  0x02 - 0x04 - slave
    //PAKIET DANYCH:
    //  type of packet 1B            - 0x01
    //  recievers address 1B
    //  senders address 1B
    //  destination address 1B
    //  time to live 1B
    //  type of recipient 1B         - 0x01 master, 0x02 slave
    //  next packet 1B               - 0x00 brak, 0x01 wystêpuje
    //  next packet number 1B        - opcjonalne
    //  priority 1B
    //  ACK 1B
    //  data length 1B               - dodawane w data_gen()
    //  data 127B                    - dodawane w data_gen()
    //  CRC 2B                       - dodawane w crc16()

    vector<int>data1 = { 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01 };
    vector<int>data2 = { 0x01, 0x01, 0x03, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01 };
    vector<int>data3 = { 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01 };

    //PAKIET ACK:
    //  type of packet 1B            - 0x02
    //  recievers address 1B
    //  senders address 1B
    //  destination address 1B
    //  time to live 1B
    //  CRC 2B                       - dodawane w crc16()

    vector<int> ack1 = { 0x02, 0x02, 0x01, 0x02, 0x02 };
    vector<int> ack2 = { 0x02, 0x03, 0x01, 0x03, 0x02 };
    vector<int> ack3 = { 0x02, 0x04, 0x01, 0x04, 0x02 };

    //PAKIET UWIERZYTELNIAJ¥CY:
    //  type of packet 1B            - 0x03
    //  recievers address 1B
    //  senders address 1B
    //  destination address 1B
    //  time to live 1B
    //  ID 32B                       - dodawanie w id_gen()
    //  CRC 2B                       - dodawane w crc16()

    vector<int> auth1 = { 0x03, 0x01, 0x02, 0x01, 0x02 };
    vector<int> auth2 = { 0x03, 0x01, 0x03, 0x01, 0x02 };
    vector<int> auth3 = { 0x03, 0x01, 0x04, 0x01, 0x02 };

    //ODPOWIEDZ NA PAKIET UWIERZYTELNIAJACY:
    //  type of packet 1B            - 0x04
    //  recievers address 1B
    //  senders address 1B
    //  destination address 1B
    //  time to live 1B
    //  ID 32B                       - dodawane w id_gen()
    //  CRC 2B                       - dodawane w crc16()

    vector<int> auth_answ1 = { 0x04, 0x02, 0x01, 0x02, 0x02 };
    vector<int> auth_answ2 = { 0x04, 0x03, 0x01, 0x03, 0x02 };
    vector<int> auth_answ3 = { 0x04, 0x04, 0x01, 0x04, 0x02 };

    //PAKIET ROZG£OSZENIOWY:
    //  type of packet 1B            - 0x05
    //  recievers address 1B
    //  senders address 1B
    //  time to live 1B
    //  CRC 2B                       - dodawane w crc16()

    vector<int> broadcast1 = { 0x05, 0x01, 0x01, 0x02 };
    vector<int> broadcast2 = { 0x05, 0x02, 0x01, 0x02 };
    vector<int> broadcast3 = { 0x05, 0x03, 0x01, 0x02 };
    //---------------------------------------------------------

    SHA256 sha256;
    string id_m = "master";
    string id_s1 = "slave1";
    string id_s2 = "slave2";
    string id_s3 = "slave3";

    vector<int> auth1_c;     //auth
    vector<int> auth2_c;
    vector<int> auth3_c;

    vector<int> broadcast1_c;     //broadcast
    vector<int> broadcast2_c;
    vector<int> broadcast3_c;

    vector<int> auth_answ1_c;    //auth answear
    vector<int> auth_answ2_c;
    vector<int> auth_answ3_c;

    vector<int> data1_c;     //data
    vector<int> data2_c;
    vector<int> data3_c;

    vector<int> ack1_c;    //ack
    vector<int> ack2_c;
    vector<int> ack3_c;

    vector<float> Re;       //modulation
    vector<float> Im;

    char nbr;

    vector<complex<float>> signal;
    vector<complex<float>> tdma_signal;
    vector<complex<float>> aloha_signal;

    //tworzenie 1. pakietu rozproszeniowego
    hex2bin(preamb_synch, broadcast1_c);
    crc16(broadcast1);
    hex2bin(broadcast1, broadcast1_c);
    //tworzenie 2. pakietu rozproszeniowego
    hex2bin(preamb_synch, broadcast2_c);
    crc16(broadcast2);
    hex2bin(broadcast2, broadcast2_c);
    //tworzenie 2. pakietu rozproszeniowego
    hex2bin(preamb_synch, broadcast3_c);
    crc16(broadcast3);
    hex2bin(broadcast3, broadcast3_c);

    //tworzenie 1. pakietu uwierzytalniaj¹cego
    hex2bin(preamb_synch, auth1_c);
    id_gen(id_s1, auth1);
    crc16(auth1);
    hex2bin(auth1, auth1_c);
    //tworzenie 2. pakietu uwierzytelniajacego
    hex2bin(preamb_synch, auth2_c);
    id_gen(id_s2, auth2);
    crc16(auth2);
    hex2bin(auth2, auth2_c);
    //tworzenie 3. pakietu uwierzytelniajacego
    hex2bin(preamb_synch, auth3_c);
    id_gen(id_s3, auth3);
    crc16(auth3);
    hex2bin(auth3, auth3_c);

    //tworzenie 1. odpowiedzi na pakiet uwierzytelniaj¹cy
    hex2bin(preamb_synch, auth_answ1_c);
    id_gen(id_m, auth_answ1);
    crc16(auth_answ1);
    hex2bin(auth_answ1, auth_answ1_c);
    //tworzenie 2. odpowiedzi na pakiet uwierzytelniajacy
    hex2bin(preamb_synch, auth_answ2_c);
    id_gen(id_m, auth_answ2);
    crc16(auth_answ2);
    hex2bin(auth_answ2, auth_answ2_c);
    //tworzenie 3. odpowiedzi na pakiet uwierzytelniajacy
    hex2bin(preamb_synch, auth_answ3_c);
    id_gen(id_m, auth_answ3);
    crc16(auth_answ3);
    hex2bin(auth_answ3, auth_answ3_c);

    //tworzenie 1. pakietu danych
    hex2bin(preamb_synch, data1_c);
    data_gen(data1);
    crc16(data1);
    hex2bin(data1, data1_c);
    //tworzenie 2. pakietu danych
    hex2bin(preamb_synch, data2_c);
    data_gen(data2);
    crc16(data2);
    hex2bin(data2, data2_c);
    //tworzenie 3. pakietu danych
    hex2bin(preamb_synch, data3_c);
    data_gen(data3);
    crc16(data3);
    hex2bin(data3, data3_c);

    //tworzenie 1. ACK
    hex2bin(preamb_synch, ack1_c);
    crc16(ack1);
    hex2bin(ack1, ack1_c);
    //tworzenie 2. ACK
    hex2bin(preamb_synch, ack2_c);
    crc16(ack2);
    hex2bin(ack2, ack2_c);
    //tworzenie 3. ACK
    hex2bin(preamb_synch, ack3_c);
    crc16(ack3);
    hex2bin(ack3, ack3_c);

   choice(nbr);
   if (nbr == '1') {        //generowanie sygnalu z wielodostepem TDMA
           tdma_frame1_auth(broadcast1_c, auth1_c, auth_answ1_c, data1_c, ack1_c, signal, tdma_signal);
           tdma_frame2_auth(broadcast2_c, auth2_c, auth_answ2_c, data2_c, ack2_c, signal, tdma_signal);
           tdma_frame3_auth(broadcast3_c, auth3_c, auth_answ3_c, data3_c, ack3_c, signal, tdma_signal);
       for (int i = 0; i < 60; i++) {
          tdma_frame1(broadcast1_c, data1_c, ack1_c, signal, tdma_signal);
          tdma_frame2(broadcast2_c, data2_c, ack2_c, signal, tdma_signal);
          tdma_frame3(broadcast3_c, data3_c, ack3_c, signal, tdma_signal);
         }
    usrp_streaming(tdma_signal);    //nadawanie wygenerowanego sygnalu
}
         else if(nbr == '2') {      //generowanie sygnalu z wielodostepem ALOHA
         aloha_auth(broadcast1_c, auth1_c, auth_answ1_c, data1_c, ack1_c, signal, aloha_signal);
           aloha_auth(broadcast2_c, auth2_c, auth_answ2_c, data2_c, ack2_c, signal, aloha_signal);
           aloha_auth(broadcast3_c, auth3_c, auth_answ3_c, data3_c, ack3_c, signal, aloha_signal);
        for (int i = 0; i < 200; i++) {
            aloha(broadcast1_c,  data1_c, ack1_c, signal, aloha_signal);
            aloha(broadcast2_c,  data2_c, ack2_c, signal, aloha_signal);
            aloha(broadcast3_c,  data3_c, ack3_c, signal, aloha_signal);
            if (i == 3 || i == 20 || i == 40 || i == 70 || i == 132){
            aloha_collision(broadcast1_c, broadcast2_c,  data1_c, data2_c, ack1_c, ack2_c, signal, aloha_signal);       //dodawanie kolizji w 3, 20 ,40 , 70 oraz 132 iteracji
          }
       }
    usrp_streaming(aloha_signal);   //nadawanie wygenerowanego sygnalu
   }
       return 0;
}

//Funkcje pomocnicze

void data_gen(vector<int>& packet) {                       //generowanie losowych danych
   int x = (rand() % 25)+230;
   packet.push_back(x);
   for (int i = 0; i < x; i++) {
      int y = rand() % 255 + 1;
       packet.push_back(y+1);
   }
   sleep(1);
}

void crc16(vector<int>& data){                            //obliczanie sumy kontrolnej po wszystkich bitach pakietu
    int crc;
    unsigned char data_crc[data.size()];
    copy(data.begin(), data.end(), data_crc);
    boost::crc_ccitt_type result;
    result.process_bytes(data_crc, data.size());
    crc = result.checksum();
    int crc1 = crc & 0xFF;
    int crc2 = crc >> 8;
    data.push_back(crc2);
    data.push_back(crc1);
}

void id_gen(string word, vector<int>& data) {              //obliczanie pola identyfukujacego
    SHA256 sha256;
    string str = sha256(word);
    int NumSubstrings = str.length() / 2;
    vector<string> id;
    for (int i = 0; i < NumSubstrings; i++) {
        id.push_back(str.substr(i * 2, 2));
        stringstream ss;
        int j;
        ss << hex << id[i];
        ss >> j;
        data.push_back(j);
    }
    cout << endl;
}

void hex2bin(vector<int> hex, vector<int>& bits) {          //przeliczanie calego pakietu z hex do bin
    int z;
    for (int i = 0; i < hex.size(); i++) {
        if ((hex[i] | 0x80) == hex[i]) {
            z = 1;
           bits.push_back(z);
        }
        else {
            z = 0;
          bits.push_back(z);
        }
        if ((hex[i] | 0x40) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x20) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x10) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x08) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x04) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x02) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }
        else {
            z = 0;
            bits.push_back(z);
        }
        if ((hex[i] | 0x01) == hex[i]) {
            z = 1;
            bits.push_back(z);
        }

        else {
            z = 0;
            bits.push_back(z);
        }
    }

}

void modulation(vector<int>& binary_data, vector<complex<float> >& sign) {  //funkcja realizujaca modulacje QPSK w pasmie podstawowym
    vector<float> Re;
    vector<float> Im;
    vector<float> buff;
    sign.clear();
    for (int i = 0; i < binary_data.size()/2; i++) {                //dzielenie ciagu binarnego na czesci Re i Im
         Re.push_back(binary_data[2*i]);
         Im.push_back(binary_data[2*i+1]);
    }

       for (int i = 0; i < Re.size(); i++) {                        //dodawanie 8 probek na symbol w czesci Re sygnalu
            if (Re[i] == 0) {
                buff.insert(buff.end(), 8, 0);
            }
            else {
                buff.insert(buff.end(), 8, 1);
            }
        }
        Re.clear();
        for (int i = 0; i < buff.size(); i++) {
           Re.push_back(buff[i]);
        }
        buff.clear();

        for (int i = 0; i < Im.size(); i++) {                        //dodawanie 8 probek na symbol w czesci Im sygnalu
            if (Im[i] == 0) {
                buff.insert(buff.end(), 8, 0);
            }
            else {
                buff.insert(buff.end(), 8, 1);
            }
        }
        Im.clear();
        for (int i = 0; i < buff.size(); i++) {
            Im.push_back(buff[i]);
        }

        for (int i = 0; i < Re.size(); i++) {                       //przypisywanie odpowiednich wartosci napiecia
            if (Re[i] == 0 && Im[i] == 0) {
                Re[i] = 0.7;
                Im[i] = 0.7;
            }
            else if (Re[i] == 0 && Im[i] == 1) {
                Re[i] = 0.7;
                Im[i] = -0.7;
            }
            else if (Re[i] == 1 && Im[i] == 0) {
                Re[i] = -0.7;
                Im[i] = 0.7;
            }
            else {
                Re[i] = -0.7;
                Im[i] = -0.7;
            }
        }
        for (int i = 0; i < Re.size(); i++) {
            complex<float> x(Re[i], Im[i]);
            sign.push_back(x);
        }
  }

void tdma_1(vector<complex<float> >mod_sign, vector<complex<float> >&tdma){       //transmisja wezla 0x01
    int y = rand() % 500 + 250;
    vector<complex<float> > tdma_sign;
    tdma_sign.insert(tdma_sign.end(), y, 0);
    for (int i = 0; i < mod_sign.size(); i++) {
        tdma_sign.push_back(mod_sign[i]);
    }

    do {
        tdma_sign.push_back(0);
    } while (tdma_sign.size() < 10000);
    tdma_sign.insert(tdma_sign.end(), 30000, 0);

    for (int i = 0; i < tdma_sign.size(); i++) {
        tdma.push_back(tdma_sign[i]);
    }

}

void tdma_2(vector<complex<float> >mod_sign, vector<complex<float> >&tdma) {      //transmisja wezla 0x02
    int y = rand() % 500 + 250;
    vector<complex<float> > tdma_sign;
    int x = 10000;
    tdma_sign.insert(tdma_sign.end(), x, 0);
    tdma_sign.insert(tdma_sign.end(), y, 0);
    for (int i = 0; i < mod_sign.size(); i++) {
        tdma_sign.push_back(mod_sign[i]);
    }

    for (int i = 0; i < (40000 - (mod_sign.size() + y + x)); i++) {
        tdma_sign.push_back(0);
    }
    for (int i = 0; i < tdma_sign.size(); i++) {
        tdma.push_back(tdma_sign[i]);
    }
}

void tdma_3(vector<complex<float> >mod_sign, vector<complex<float> >& tdma) {     //transmisja wezla 0x03
    int y = rand() % 500 + 250;
    vector<complex<float> > tdma_sign;
    int x = 20000;
    tdma_sign.insert(tdma_sign.end(), x, 0);
    tdma_sign.insert(tdma_sign.end(), y, 0);
    for (int i = 0; i < mod_sign.size(); i++) {
        tdma_sign.push_back(mod_sign[i]);
    }

    for (int i = 0; i < (40000 - (mod_sign.size() + y + x)); i++) {
        tdma_sign.push_back(0);
    }
    for (int i = 0; i < tdma_sign.size(); i++) {
        tdma.push_back(tdma_sign[i]);
    }
}

void tdma_4(vector<complex<float> >mod_sign, vector<complex<float> >& tdma) {     //transmisja wezla 0x04
    int y = rand() % 500 + 250;
    vector<complex<float> > tdma_sign;
    int x = 30000;
    tdma_sign.insert(tdma_sign.end(), x, 0);
    tdma_sign.insert(tdma_sign.end(), y, 0);
    for (int i = 0; i < mod_sign.size(); i++) {
        tdma_sign.push_back(mod_sign[i]);
    }

    for (int i = 0; i < (40000 - (mod_sign.size() + y + x)); i++) {
        tdma_sign.push_back(0);
    }
    for (int i = 0; i < tdma_sign.size(); i++) {
        tdma.push_back(tdma_sign[i]);
    }
}

void tdma_frame1_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal ) {     //scenariusz pierwszej komunikacji wezla 0x02 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(auth, signal);
    tdma_2(signal, tdma_signal);
    modulation(auth_ans, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_2(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}

void tdma_frame1(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal ) {     //scenariusz komunikacji wezla 0x02 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_2(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}


void tdma_frame2_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal) {     //scenariusz pierwszej komunikacji wezla 0x03 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(auth, signal);
    tdma_3(signal, tdma_signal);
    modulation(auth_ans, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_3(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}

void tdma_frame2(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal) {     //scenariusz komunikacji wezla 0x03 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_3(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}

void tdma_frame3_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal) {     //scenariusz pierwszej komunikacji wezla 0x04 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(auth, signal);
    tdma_4(signal, tdma_signal);
    modulation(auth_ans, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_4(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}

void tdma_frame3(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> > signal, vector<complex<float> >& tdma_signal) {     //scenariusz komunikacji wezla 0x04 z 0x01
    modulation(br, signal);
    tdma_1(signal, tdma_signal);
    modulation(dat, signal);
    tdma_4(signal, tdma_signal);
    modulation(ack, signal);
    tdma_1(signal, tdma_signal);
}

int rand_aloha() {                      //losowe odstepy w czasie miedzy pakietami
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(4000, 15000);
    return distrib(gen);
}

void aloha_auth(vector<int> br, vector<int>auth, vector<int> auth_ans, vector<int>dat, vector<int> ack, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal) {        //realizacja dostepu wielokrotnego ALOHA
    int y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(br, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(auth, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(auth_ans, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(dat, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(ack, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
}

void aloha(vector<int> br, vector<int>dat, vector<int> ack, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal) {        //realizacja dostepu wielokrotnego ALOHA
    int y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(br, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(dat, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(ack, signal);
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
}

void aloha_collision(vector<int> br, vector<int> br2, vector<int>dat, vector<int> dat2, vector<int> ack, vector<int> ack2, vector<complex<float> >& signal, vector<complex<float> >& aloha_signal){     //realizacja kolizji w wielodostępie ALOHA
    int y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(br, signal);                                 //pakiet rozgloszeniowy 1.
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
     y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(dat, signal);                                //pakiet danych 1.
    for (int i = 0; i < (signal.size()/5)*4; i++) {
        aloha_signal.push_back(signal[i]);
    }
    modulation(dat2, signal);                                //kolizja - pakiet danych 2.
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(dat, signal);                                //pakiet danych 1.
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(ack, signal);                                //ack 1
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(br2, signal);                                 //pakiet rozgloszeniowy 2.
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
     y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(dat2, signal);                                //pakiet danych 2.
    for (int i = 0; i < (signal.size()/5)*4; i++) {
        aloha_signal.push_back(signal[i]);
    }
    y = rand_aloha();
    aloha_signal.insert(aloha_signal.end(), y, 0);
    modulation(ack2, signal);                                //ack 2
    for (int i = 0; i < signal.size(); i++) {
        aloha_signal.push_back(signal[i]);
    }
}

void choice(char& nbr) {                                        //wybor metody wielodostepu TDMA/ALOHA
    cout << endl << "1. TDMA" << endl << "2. ALOHA" << endl;
    cin >> nbr;
    switch (nbr)
    {
    case '1':
        cout << endl << "TDMA " << endl;
            break;
    case '2':
        cout << endl << "ALOHA " << endl;
            break;

    default:
        choice(nbr);
        break;
    }
}

void sig_int_handler(int){
    stop_signal_called = true;
}

void usrp_streaming(vector <complex <float> > &tx_signal) {         //komunikacja z urządzeniem USRP 2920 NI
    string args = "";
    uhd::usrp::multi_usrp::sptr usrp = uhd::usrp::multi_usrp::make(args);
    string ref = "internal";
    float rate = 1e6;                   //czestotliwosc probkowania 1 Mhz
   usrp->set_tx_rate(rate);
    float freq = 868e6;                 //czestotliwosc srodkowa 868 MHz
    usrp->set_tx_freq(freq);
    float gain = 5;                     //wzmocnienie 5 dB
    usrp->set_tx_gain(gain);
    uhd::stream_args_t stream_args("fc32");
    uhd::tx_streamer::sptr tx_stream = usrp->get_tx_stream(stream_args);
    uhd::tx_metadata_t md;
    signal(SIGINT, sig_int_handler);
    complex<float> * SAMPLES = new complex<float> [SAMPS_NUM];
    int counter = 0;
	int x = 0;

  while(!stop_signal_called)
    {
    md.start_of_burst = true;
    md.end_of_burst = false;
    md.has_time_spec = true;
    md.time_spec = usrp->get_time_now() + uhd::time_spec_t(0.1);


   while( (!md.end_of_burst) && (!stop_signal_called))
    {
        if(x == tx_signal.size()){
            md.end_of_burst = true;
            md.has_time_spec = false;
                }
            SAMPLES[counter] = tx_signal[x];
            counter++;
            x++;

        if (counter == SAMPS_NUM ){
            tx_stream->send(&SAMPLES[ (0) ],SAMPS_NUM, md, 0.5);    //transmisja sygnalu
            counter =0;
           fill_n(SAMPLES, SAMPS_NUM, 0);
        }
    }
delete SAMPLES;
break;
    }
}
