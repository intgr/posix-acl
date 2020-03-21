# vagrant plugin install vagrant-libvirt

Vagrant.configure("2") do |config|
  config.vm.box = "freebsd/FreeBSD-13.0-CURRENT"

  config.vm.provision "shell", inline: <<-SHELL

    sudo pkg install -y curl git

    ln -sf .cargo/bin .

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

    git clone https://github.com/Stebalien/acl-sys
    git clone https://github.com/intgr/posix-acl

  SHELL

  # config.vm.synced_folder ".", "/home/vagrant/posix-acl", :nfs => true, id: "vagrant-root"
  # config.vm.synced_folder ".", "/vagrant", :nfs => true, id: "vagrant-root"
end
