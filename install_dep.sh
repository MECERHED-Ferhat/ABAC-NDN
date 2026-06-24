echo "Mise à jour du système"
sudo apt update -y && sudo apt upgrade -y

echo "Installation des paquets requis"
sudo apt install -y build-essential cmake git wget curl pkg-config \
    libssl-dev libpcap-dev libsqlite3-dev libboost-all-dev \
    bison flex m4 doxygen python3-minimal python3-pip \
    libprotobuf-dev protobuf-compiler libgmp-dev flex bison

WORKDIR=~/Documents/Build
mkdir -p "$WORKDIR"
cd "$WORKDIR"

#######################################
################# GMP #################
#######################################
echo "GMP Setup"
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz -O gmp.tar.xz
tar -xf gmp.tar.xz
cd gmp-6.3.0
./configure
make
sudo make install
cd "$WORKDIR"

#######################################
############### CRYPTOPP ##############
#######################################
echo "CryptoPP setup"
git clone https://github.com/weidai11/cryptopp.git
cd cryptopp
make
sudo make install
cd "$WORKDIR"

#######################################
################# PBC #################
#######################################
echo "PBC Setup"
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -O pbc.tar.gz
tar -xzf pbc.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install
cd "$WORKDIR"

#######################################
############### ndn-cxx ###############
#######################################
echo "ndn-cxx setup"
git clone https://github.com/named-data/ndn-cxx.git
cd ndn-cxx
./waf configure
./waf
sudo ./waf install
sudo ldconfig
cd "$WORKDIR"

#######################################
################# NFD #################
#######################################
echo "nfd setup"
git clone --recursive https://github.com/named-data/NFD.git
cd NFD
./waf configure
./waf
sudo ./waf install
sudo ldconfig
cd "$WORKDIR"

#######################################

echo "Vérification"
sudo ldconfig
ldconfig -p | grep -E "libndn-cxx|libcryptopp|libgmp|libpbc" || true

echo "Terminé"
