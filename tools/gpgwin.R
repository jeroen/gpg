# Downloads
if(!file.exists('bin/gpg.exe')){
  download.file('https://github.com/jeroen/gpg/releases/download/windows/gnupg-w32cli-1.4.23.zip', 'wingpg.zip')
  unzip('wingpg.zip')
  unlink('wingpg.zip')
}
