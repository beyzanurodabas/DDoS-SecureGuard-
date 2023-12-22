import socket
import threading

# Sunucu ayarları
HOST = "0.0.0.0"
PORT = 80

# TCP soketi oluştur
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)  # 1 bağlantıyı dinle

print(f"Sunucu {HOST}:{PORT} üzerinde çalışıyor...")

packet_count = 0  # Başlangıçta paket sayısını sıfırla

def server():
    global packet_count
    while True:
        # İstemci bağlantısını kabul et
        client_socket, addr = server_socket.accept()

        # Veriyi al
        data = client_socket.recv(1024)

        # Gelen veriyi ekrana direkt olarak yazdır
        #print(f"Gelen Veri: {data} - {addr}")

        # İstemciye cevap gönder
        response_data = "Gelen veri alındı!\n "
        client_socket.send(response_data.encode('utf-8'))

        # Paket sayısını artır
        packet_count += 1
        #print(f"Toplam Paket Sayısı: {packet_count}")

        # Bağlantıyı kapat
        client_socket.close()

# Server'ı bir thread içinde başlat
server_thread = threading.Thread(target=server)
server_thread.start()

def get_total_connections():
    return packet_count
