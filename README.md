# gpg

> *GNU Privacy Guard for R*

[![Build Status](https://travis-ci.org/jeroen/gpg.svg?branch=master)](https://travis-ci.org/jeroen/gpg)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/jeroen/gpg?branch=master&svg=true)](https://ci.appveyor.com/project/jeroen/gpg)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/gpg)](http://cran.r-project.org/package=gpg)
[![CRAN RStudio mirror downloads](http://cranlogs.r-pkg.org/badges/gpg)](http://cran.r-project.org/web/packages/gpg/index.html)
[![Github Stars](https://img.shields.io/github/stars/jeroen/gpg.svg?style=social&label=Github)](https://github.com/jeroen/gpg)

Bindings to GPG for creating and verifying OpenGPG (RFC4880)
signatures. This is not a standalone library; GPG needs to be installed
on the system. On Windows you need GPG4Win or similar, on other systems
use the GPGME library.

## Documentation

About the R package:

 - Vignette: [Using GPG in R](https://cran.r-project.org/web/packages/gpg/vignettes/intro.html)

Other resources:

 - [The GNU Privacy Handbook](https://www.gnupg.org/gph/en/manual.html)


## Hello World

The Debian backports archives on CRAN are signed with the key of Johannes Ranke (CRAN Debian archive) <jranke@uni-bremen.de> with key fingerprint __6212 B7B7 931C 4BB1 6280  BA13 06F9 0DE5 381B A480__.

Let's import his key so that we can verify the [Release](https://cran.r-project.org/bin/linux/debian/buster-cran35/Release) file, which contains checksums for all files in the repository:

```r
# Take out the spaces
johannes <- gsub(" ", "", "6212 B7B7 931C 4BB1 6280  BA13 06F9 0DE5 381B A480")
gpg_recv(johannes)

# Verify the file
library(curl)
curl_download('https://cran.r-project.org/bin/linux/debian/buster-cran35/Release', 'Release')
curl_download('https://cran.r-project.org/bin/linux/debian/buster-cran35/Release.gpg', 'Release.gpg')
gpg_verify('Release', 'Release.gpg')
```


## Installation

Binary packages for __OS-X__ or __Windows__ can be installed directly from CRAN:

```r
install.packages("gpg")
```

Installation from source on Linux or OSX requires [`GPGME`](https://www.gnupg.org/(es)/related_software/gpgme/index.html). On __Debian__ or __Ubuntu__ install [libgpgme11-dev](https://packages.debian.org/testing/libgpgme11-dev) directly from Universe:

```
sudo apt-get install -y libgpgme11-dev
```

On __Fedora__ and __CentOS__ we need [gpgme-devel](https://src.fedoraproject.org/rpms/gpgme):

```
sudo yum install gpgme-devel
````

On __OS-X__ use [gpgme](https://github.com/Homebrew/homebrew-core/blob/master/Formula/gpgme.rb) from Homebrew:

```
brew install gpgme
```

On __Solaris 10__ we can have [gpgme_dev](https://www.opencsw.org/packages/CSWgpgme-dev/) from [OpenCSW](https://www.opencsw.org/):
```
pkgadd -d http://get.opencsw.org/now
/opt/csw/bin/pkgutil -U
/opt/csw/bin/pkgutil -y -i gpgme_dev 
```

