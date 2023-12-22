import socket
import threading
import os
import statistics
import time
import logging
import binascii
import sys
import sqlite3
from scapy.all import sniff, IP,TCP, UDP,Raw
from scapy.layers.http import HTTPRequest
import re
from scapy.all import *
import os, statistics, time, logging, re


logger = logging.getLogger('attack_detector') ##'attack_detector' adlı bir logger oluşturuldu.
##setLevel metodu, log mesajlarının hangi seviyede (DEBUG, INFO, WARNING, ERROR, CRITICAL) görüntüleneceğini belirler. 
#Burada logging.DEBUG seviyesi seçilmiş, bu da en düşük seviyeden en yüksek seviyeye kadar tüm mesajların görüntüleneceği anlamına gelir.
logger.setLevel(logging.DEBUG)

# log mesajlarını konsola yönlendirmek üzere bir StreamHandler eklenir.
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

#Formatter, log mesajlarının nasıl görüntüleneceğini belirler. Burada bir tarih/saat damgası, log seviyesi ve mesaj içeriği kullanılmış bir format belirlenmiş.
#datefmt parametresi, tarih/saat formatını belirler.
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S%p')
ch.setFormatter(formatter)

#Oluşturulan StreamHandler (ch) işleyici, logger'a eklenir.
logger.addHandler(ch)

#Saldırganın engellenip engellenmeyeceğini belirleyen bir bayrak
block_attacker = False

#Saldırıları kontrol etme aralığı, saniye cinsinden. 
sleep_interval = 2

#Bağlantı sayısı eşiği.
connection_threshold = 10 #1000 idi önceden tekrar bak

#Önceki bağlantı sayısını depolamak için liste
previous_connections = []

# Bildirim fonksiyonu
def send_notification(message):
    print(f"Bildirim: {message}")
    
sys.path.append(r"C:\Users\beyza\OneDrive\Masaüstü\tcp_server")
from server import get_total_connections  # server.py dosyanızdaki fonksiyonu import edin


# DDoS Saldırısı Tespiti
def detect_ddos():
    global previous_connections
    while True:
        try:
            # Ağ etkinliğinin anormal olup olmadığını belirlemek için istatistiksel analiz kullanıyoruz
            paket_sayisi = get_total_connections()
            #Bağlantı sayısını bir listeye ekler. Bu, geçmiş bağlantı sayılarına erişimi sağlar.
            previous_connections.append(paket_sayisi)

            if len(previous_connections) >= 10: #listedeki elemanlar 10dan fazlaysa analizi gerçekleştiriyoruz
                mean = statistics.mean(previous_connections) # listedeki sayıların ortalamasını (mean) hesaplar.
                stddev = statistics.stdev(previous_connections) # listedeki sayıların standart sapmasını (stddev) hesaplar.
                #Bu adımların amacı, previous_connections listesindeki bağlantı sayıları üzerinde bir istatistik analizi yaparak normal bağlantı davranışını belirlemektir. 
                #Eğer bağlantı sayısı belirli bir eşiği aşarsa ve ortalamadan belirgin şekilde yüksekse, potansiyel bir DDoS saldırısı uyarısı yapılabilir.

                #Bağlantı sayısı eşiğin üzerinde ve ortalamanın 2katından fazlaysa uyarı gönder
                if paket_sayisi > connection_threshold and paket_sayisi > (mean + 2 * stddev):
                    #Saldırıyı Başlatan IP Adresini Bulma
                    attacker = None #saldırıyı başlatan ip adresi
                    #os.popen fonksiyonu, netstat komutunu çalıştırır ve sonucunu result adlı bir dosya nesnesine bağlar.
                    with os.popen("netstat -an | FindStr /R /C:\":80 \"") as result:
                        for line in result: #result dosyasındaki her satırı kontrol eder.
                            #re.search fonksiyonu, her satır üzerinde bir IP adresi araması yapar ((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ifadesi bir IP adresini eşleştirmek için kullanılır).
                            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                            if match: #eşleşme varsa
                                attacker = match.group() #eşleşen ip attacker oldu
                                break
                    #Saldırıyı Loglama ve Bloklama
                    #Potansiyel saldırıyı loglar ve uyarı seviyesinde bir log mesajı oluşturur.
                    #Saldırıyı başlatan IP'yi bloklamak istiyorsanız, bu IP'yi Windows güvenlik duvarına ekler.
                    #logger.warning ifadesi, log kaydını uyarı seviyesinde oluşturur. Bu, loglama düzeylerinden biridir ve genellikle önemli ancak kritik olmayan olaylar için kullanılır.
                    logger.warning('Potansiyel DDoS Attack [Bağlantı Sayısı=' + format(paket_sayisi) + '] [attacker=' + attacker + ']')

                    if block_attacker: #block_attacker değişkeni True ise (yani saldırganın engellenmesi etkinleştirilmişse
                        print("aa")
                        # saldırganın IP adresini Windows güvenlik duvarına bir kural ekleyerek engeller.
                        #netsh advfirewall firewall add rule komutu, bir güvenlik duvarı kuralı eklemek için kullanılır.
                        #name="Block IP" ifadesi, eklenen kuralın adını belirler.
                        #dir=in ifadesi, kuralın gelen (incoming) bağlantıları kontrol etmesini sağlar.
                        #action=block ifadesi, belirlenen şartlara uyan bağlantıları engeller.
                        #remoteip={attacker} ifadesi, kuralın uygulanacağı IP adresini belirler. 
                        os.system(f'netsh advfirewall firewall add rule name="Block IP" dir=in action=block remoteip={attacker}')
                    
                    #Eğer istatistik analizi yapmak için yeterli veri toplandıysa, geçmiş bağlantıları temizler.
                    previous_connections = []
                else:
                    logger.debug('Bağlantılar normal [Bağlantı Sayısı =' + format(paket_sayisi) + ']')
                    previous_connections.pop(0)

            else:
                logger.debug('Normal bağlantı miktarını belirlemek için yeterli veri yok [Bağlantı Sayısı =' + format(paket_sayisi) + ']')
        except Exception as e:
            logger.error(f"Hata oluştu: {str(e)}")

        time.sleep(sleep_interval)  # 60 saniye bekleme süresi (istenilen sıklıkta ayarlayabilirsiniz)

if __name__ == "__main__":
    detect_ddos()







    
