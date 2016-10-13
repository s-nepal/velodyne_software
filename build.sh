#!/bin/bash



#export portName="eth10"
virtual_ethernet()
{
	echo "setting virtual ethernet port"
	sudo modprobe dummy
	lsmod | grep dummy

	if (sudo ip link set name eth10 dev dummy0 2> /dev/null); then
		echo "succesfully created a virtual ethernet"
		sudo ifconfig eth10 up 
	else 
		echo "error in creating vitual ethernet port"
		echo -n "Do you want to clean up existing eth10 [Y/n]"
		sudo ifconfig eth10 up 
		read character
		case $character in
			Y)
				echo "cleaning up existing device"
				sudo ip link delete eth10 type dummy
				sudo rmmod dummy
				;;
			n)
				exit 1
				;;
		esac
	fi
}


LSUSBINFO="$(lsusb | grep PEAK | cut -d' ' -f 6)"

sudo slcand -o -c -s0 /dev/$LSUSBINFO can0
(sudo ifconfig can0 up) 2> /dev/null
if [ "$?" = "0" ]; then
	echo "CAN device is connected"
else
	echo "CAN device is not connected"
fi

virtual_ethernet