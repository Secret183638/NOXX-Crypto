# NOXX Crypto

## Installing
``clang++ -O3 -o noxx noxx.cpp -lssl -lcrypto -std=c++17
sudo cp noxx /usr/local/bin/``

# Using
``noxx -c secret.txt secret.noxx``    # Encrypt
``noxx -d secret.noxx secret.txt``    # Decrypt

# Examples
``noxx -c photo.jpg photo.noxx``
``noxx -c backup.tar.gz backup.noxx``
