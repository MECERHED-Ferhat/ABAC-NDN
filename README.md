# ABAC-NDN
 An Open-Source Security Library for Attribute-Based Access Control in NDN


## How to install

### 0. Pre-requisites 

### 1. Move to the directory ABAC-NDN & compile the cmake

```bash
cd ABAC-NDN
cmake .
```

### 2. Finish the configuration with make

```bash
make
```

### 3. Install the package with make install & ldconfig

```bash
sudo make install
sudo ldconfig
```

### 4. Verify if the package is installed correctly

```bash
ls /usr/local/lib | grep ABAC
ls /usr/local/include | grep ABAC 
```


