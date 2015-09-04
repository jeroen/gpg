Contains:

  - gpgme-1.6.0
  - libassuan-2.3.0
  - libgpg-error-1.20

The gpgme-1.6.0/src/w32-util.c has been patched by replacing
the constant CSIDL_PROGRAM_FILES by CSIDL_PROGRAM_FILESX86.
This allows gpgme to find gpg4win on Windows 64 systems.

Each library was compiled using msys and rtools 4.6.3 with

  CFLAGS="-m32" ./configure --enable-static --disable-shared && make

And for win64:

  CFLAGS="-m64" ./configure --enable-static --disable-shared && make

Note that besides the library, gpgme also requires the gpgme-w32spawn.exe
utility to be present in the directory of the running application.
