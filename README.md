PluraCoin (PLURA) - Anonymous cryptocurrency with higher resistance against  blockchain analysis focused on crypto adoption by masses through affordable Crypto e-Commerce Payment Solution (CEPS)

## Building PluraCoin 

### On *nix (Ubuntu 20.04 LTS reccommended)

Dependencies: GCC 4.7.3 or later, CMake 2.8.6 or later, and Boost 1.55, OpenSSL.

You may download them from:

* http://gcc.gnu.org/
* http://www.cmake.org/
* http://www.boost.org/

* Alternatively, it may be possible to install them using a package manager:

````
sudo apt-get install build-essential cmake libboost-all-dev libssl-dev -y
````

Ubuntu 20.04 LTS already comes with Git preinstalled. To check if you really have Git installed type:

````
git --version
````

You should get response like 

````
git version 2.25.1
````

If Git is not found then install it:

````
sudo apt-get install git -y
````

Download existing blockchain to speed up initial synchronization from 
https://blockchain.pluracoin.org/blockchain.zip
and unzip it to folder .pluracoin
````
cd ~
mkdir .pluracoin
cd .pluracoin
wget https://blockchain.pluracoin.org/blockchain.zip
unzip blockchain.zip
rm blockchain.zip

````

Now clone the PluraCoin with Git to your home directory (or wherever you want):

````
cd ~
git clone https://github.com/pluracoin/PluraCoin.git
````

To build PluraCoin, change to a directory where this file is located, and run `make`.

````
cd PluraCoin
make
````

The resulting executables can be found in `build/release/src`.

**Advanced options:**

* Parallel build: run `make -j <number of threads>` instead of `make`. You can safely run `make -j 4` on VPS with two cores and 4 GB RAM.
* Debug build: run `make build-debug`.
* Test suite: run `make test-release` to run tests in addition to building. Running `make test-debug` will do the same to the debug version.
* Building with Clang: it may be possible to use Clang instead of GCC, but this may not work everywhere. To build, run `export CC=clang CXX=clang++` before running `make`.


Start daemon 

````
cd build/release/src
./pluracoind
````

Wait for blockchain sync and you're done !

More info about daemon, wallet and simplewallet can be found in Wiki https://github.com/pluracoin/PluraCoin/wiki

---

### On Windows
Dependencies: MSVC 2013 or later, CMake 2.8.6 or later, and Boost 1.55. You may download them from:

* http://www.microsoft.com/
* http://www.cmake.org/
* http://www.boost.org/

To build, change to a directory where this file is located, and run theas commands: 
```
mkdir build
cd build
cmake -G "Visual Studio 12 Win64" ..
```

And then do Build.
Good luck!

---
