
id=$(bpftool prog list | awk '$2 == "xdp" {print $1}' | sed 's/://')
echo $id
sudo bpftool net detach xdp dev eno1 id $id
id=$(bpftool prog list | awk '$2 == "xdp" {print $1}' | sed 's/://')
echo $id
sudo bpftool net detach xdp dev eno2 id $id
id=$(bpftool prog list | awk '$2 == "xdp" {print $1}' | sed 's/://')
echo $id
sudo bpftool net detach xdp dev eno3 id $id
id=$(bpftool prog list | awk '$2 == "xdp" {print $1}' | sed 's/://')
echo $id
sudo bpftool net detach xdp dev eno4 id $id
id=$(bpftool prog list | awk '$2 == "xdp" {print $1}' | sed 's/://')
echo $id
sudo bpftool net detach xdp dev enp8s0 id $id

