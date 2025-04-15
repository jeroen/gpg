# Downloads 'gpg classic' for windows.
# Sadly the GnuPG in Rtools does not seem to work.
if(!file.exists('bin/gpg.exe')){
  download.file('https://github.com/jeroen/gpg/releases/download/windows/gnupg-w32cli-1.4.23.zip', 'wingpg.zip')
  unzip('wingpg.zip')
  unlink('wingpg.zip')
}
