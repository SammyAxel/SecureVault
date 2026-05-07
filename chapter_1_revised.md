# BAB 1
# PENDAHULUAN

## 1.1 Latar Belakang

Di era digital saat ini, pertukaran dan penyimpanan data berbasis awan (*cloud storage*) telah menjadi infrastruktur krusial bagi individu maupun organisasi. Kemudahan akses dan kolaborasi yang ditawarkan oleh layanan seperti Google Drive, Dropbox, atau OneDrive mendorong migrasi data masif ke platform-platform tersebut. Namun, fenomena ini membawa paradoks keamanan yang serius: semakin banyak data sensitif yang kita percayakan kepada pihak ketiga, semakin besar pula risiko hilangnya kedaulatan atas privasi data tersebut.

Permasalahan utama yang mendasari penelitian ini bukanlah sekadar ancaman eksternal, melainkan **model kepercayaan (*trust model*)** yang digunakan oleh sebagian besar penyedia layanan saat ini. Kritik terhadap mekanisme konvensional dapat diuraikan ke dalam dua aspek fundamental:

1.  **Kelemahan pada Enkripsi Sisi-Server (*Server-Side Encryption*)**
    Sebagian besar layanan penyimpanan awan menerapkan enkripsi pada data yang disimpan (*encryption at rest*). Namun, proses enkripsi dan pengelolaan kunci dilakukan sepenuhnya oleh penyedia layanan. Artinya, kunci untuk membuka data tersebut disimpan di infrastruktur yang sama atau dikelola oleh pihak penyedia.
    *   **Ancaman Eksternal:** Jika peretas berhasil menembus pertahanan server dan mencuri basis data kunci, maka enkripsi data pengguna menjadi tidak berguna.
    *   **Ancaman Internal (*Insider Threat*):** Administrator sistem atau karyawan yang korup pada penyedia layanan memiliki kemampuan teknis untuk mengakses data pengguna tanpa izin.
    *   **Intervensi Pihak Ketiga:** Dalam kasus hukum atau tekanan politik, penyedia layanan dapat dipaksa untuk mendekripsi dan menyerahkan data pengguna kepada otoritas, seringkali tanpa sepengetahuan pemilik data.

2.  **Penyalahgunaan Data dan Profiling**
    Dalam model tradisional, karena penyedia layanan memiliki akses ke data dalam bentuk teks terang (*plaintext*) saat pemrosesan, data tersebut rentan dianalisis untuk keperluan komersial (seperti *profiling* iklan) atau bahkan disalahgunakan untuk rekayasa sosial (*social engineering*) jika terjadi kebocoran informasi parsial.

Sebagai solusi atas permasalahan fundamental tersebut, penelitian ini mengusulkan penerapan **Arsitektur Zero-Knowledge** menggunakan mekanisme **Enkripsi Ujung-ke-Ujung (*End-to-End Encryption/E2EE*)**. Berbeda dengan model tradisional, arsitektur ini memindahkan proses kriptografi dari server ke perangkat pengguna (*client-side*).

Dalam sistem yang dibangun ini, konsep *trust* diubah secara radikal. Pihak penyedia layanan (server) diposisikan sebagai entitas yang "tidak dipercaya" (*zero trust*). Server hanya berfungsi sebagai tempat penitipan data yang telah terenkripsi (blab data) dan tidak pernah memiliki akses ke kunci enkripsi yang asli.
Implementasi teknis solusi ini menggabungkan dua algoritma kriptografi modern untuk menjamin performa dan keamanan:
*   **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode):** Digunakan untuk mengenkripsi konten *file* secara efisien. Mode GCM dipilih karena memberikan kerahasiaan (*confidentiality*) sekaligus integritas data (*integrity*), mencegah data dimodifikasi di tengah jalan tanpa terdeteksi.
*   **RSA-OAEP (Rivest–Shamir–Adleman - Optimal Asymmetric Encryption Padding):** Digunakan untuk mekanisme pertukaran kunci (*key exchange*). Kunci AES yang mengenkripsi *file* akan dibungkus (*wrapped*) menggunakan kunci publik penerima, sehingga hanya pemilik kunci privat yang sah yang dapat membukanya.

Dengan pendekatan ini, risiko kebocoran data akibat peretasan server atau penyalahgunaan internal dapat dimitigasi secara total, karena data yang bocor hanyalah sampah digital (*ciphertext*) yang tidak bermakna tanpa kunci yang tersimpan aman di perangkat pengguna.

## 1.2 Rumusan Masalah
Berdasarkan latar belakang di atas, rumusan masalah dalam penelitian ini adalah:
1.  Bagaimana merancang sistem penyimpanan data yang dapat menjamin kerahasiaan data bahkan dari penyedia layanan itu sendiri (*provider-blind*)?
2.  Bagaimana mengimplementasikan kombinasi algoritma AES-GCM dan RSA-OAEP dalam aplikasi berbasis web untuk mewujudkan arsitektur *Zero-Knowledge* dengan tetap mempertahankan kemudahan penggunaan (*usability*)?

## 1.3 Tujuan Penelitian
1.  Membangun aplikasi *file sharing* yang menerapkan enkripsi di sisi klien (*client-side encryption*) secara penuh.
2.  Membuktikan bahwa penggabungan AES-GCM dan RSA-OAEP mampu mengamankan data dari ancaman peretasan pada sisi server (*server breach*) dan akses internal tidak sah.
