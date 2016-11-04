#include <iostream>
#include <assert.h>
#include <string>
#include <fstream>
#include <vector>
#include <stdlib.h>
#include <math.h>
#include <thread>
#include <sys/wait.h>
#include <signal.h>
#include <fstream>
#include "functions.cpp"

using namespace std;
 
int main(int argc, char *argv[]) 
{	
	pcap_t *descr;
	// Define the Ethernet and CAN ports to be used
	// char *eth_port_1 = "eth0";
	// char *eth_port_2 = "eth1";
	// char *eth_port_buffer_1 = "eth10";
	// char *eth_port_buffer_2 = "eth10"; // fow now only, later change to eth11
	// char *can_port = "vcan0";

	pause_sim_kb = (unsigned int *) mmap(NULL, sizeof (*pause_sim_kb), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	// Define the 3 modes input via the command line that the code can function in
	string s[3] = {"live", "record", "offline"};

	if(argc < 2)
	{
		cout << "Input the proper option \n\t1)live\n\t2)record\n\t3)offline" << endl;
		exit(0);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	
	// Live Mode
	if(argv[1] == s[0]) 
	{	
		cout << "Live Mode Entered" << endl;
		// Create a fork to allow the data from 2 LiDAR's to be visualized in parallel
		int pid = fork();
		if(pid < 0){
			cout << "fork error" << endl;
			exit(0);
		}	
		
		else if(pid == 0){
			// Fork for visualizing and buffering data from the first lidar
			pcl::visualization::CloudViewer viewer("Data from eth0");
			thread t1(record::save_pcap, eth_port_buffer_1, "Sample_1.pcap");
			descr = pcap_open_live(eth_port_1, 1248, 1, 1, errbuf);
			if (descr == NULL) {
				cout << "pcap_open_live() failed: " << errbuf << endl;
				return 1;
			}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
			viewer.runOnVisualizationThread (viewerPsycho);
			//loop through the pcap file and extract the packets
			pcap_loop(descr, 0, live::packetHandler_I, (u_char *) &viewer);
			t1.join();
			while(!viewer.wasStopped()){
				//do nothing
			}
		}
		else {

			int pid1 = fork();
			if(pid1 == 0){
				canData();
			}
			else {
				// Fork for visualizing and buffering data from the second lidar
				pcl::visualization::CloudViewer viewer("Data from eth1");
				thread t1(record::save_pcap, eth_port_buffer_2, "Sample_2.pcap");
				thread t2(video::playback_video, 1);
				descr = pcap_open_live(eth_port_2, 1248, 1, 1, errbuf);
				if (descr == NULL) {
					cout << "pcap_open_live() failed: " << errbuf << endl;
					return 1;
				}
				viewer.runOnVisualizationThreadOnce (viewerOneOff);
				viewer.runOnVisualizationThread (viewerPsycho);

				pcap_loop(descr, 0, live::packetHandler_II, (u_char *) &viewer);

				t2.join();
				t1.join();
				int w = wait(NULL);
				int w1 = wait(NULL);
				while(!viewer.wasStopped()){
					//do nothing
				}

			}
		}
	}

	// Record Mode
	if(argv[1] == s[1])
	{	
		cout << "Record Mode Entered" << endl;
		int ret = fork();
		if(ret < 0){
			cout << "fork error in record mode" << endl;
			exit(0);
		}
		else if(ret == 0){
			// Create a text file and store CAN data in it
			close(1); //redirecting the ouput
			int fd = open("canData.txt", O_WRONLY | O_CREAT | O_TRUNC, 0660);
			if(fd < 0){
				cout << "cannot open file canData.txt" << endl;
				exit(0);
			}
			
			// Candump from can_utils is used here
			char *myargv[4] = {"./candump", "-tz", can_port, NULL};
			int myargc = 3;
			int can_return = can_main(myargc, myargv);
			cout << "return from can_main function: " << can_return << endl;

		}
		else {
			signal(SIGINT, compressFiles);
			// Create 3 threads, two for saving UDP data and none for saving video data
			thread t1(video::capture_video);
			thread t2(record::save_pcap, eth_port_1, "Sample_1.pcap");
			thread t3(record::save_pcap, eth_port_2, "Sample_2.pcap");

			t2.join();
			t3.join();
			t1.join();
			int w = wait(NULL);

			// Compresses recorded files into a tar file
			//compressFunct();
		}
		
	}

	// Offline Mode
	if(argv[1] == s[2])
	{
		cout << "Offline Mode Entered" << endl;
		cout << "extracting data from tar file ..." << endl;

		// Extracts recorded files from the compressed folder
		// if(system("tar -xzvf data.tar.gz") < 0){
		// 	cout << "error in extracting the data from tar file" << endl;
		// 	return 0;
		// }

		int pid = fork();
		if(pid < 0){
			cout << "fork error in offline mode" << endl;
			exit(0);
		}

		else if(pid == 0){
			pcl::visualization::CloudViewer viewer("Sample_1.pcap");
			descr = pcap_open_offline("Sample_1.pcap", errbuf);
			if (descr == NULL) {
				cout << "pcap_open_offline() failed: " << errbuf << endl;
				return 1;
			}
			viewer.registerMouseCallback (mouseEventOccurred, (void*) &viewer);
			viewer.registerKeyboardCallback (keyboardEventOccurred, (void*) &viewer);
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
			viewer.runOnVisualizationThread (viewerPsycho);
			//loop through the pcap file and extract the packets
			pcap_loop(descr, 0, offline::packetHandler_I, (u_char *) &viewer);

			while(!viewer.wasStopped()){
				//do nothing
			}
		} 
		else {
			 int pid1 = fork();
			 if(pid1 < 0){
			 	cout << "fork error" << endl;
			 	exit(0);
			 }
			 else if(pid1 == 0){		//displaying canData on terminal
			 	
			 	ifstream canData("canData.txt");
			 	string line, tempStrTime, strTime;
			 	float time = 0, timePrev = 0;
			 	std::string::size_type first, last;
			 	while(getline(canData, line))
			 	{
			 		while(*pause_sim_kb == 1){}
			 		canData >> strTime;
			 		first = strTime.find("(");
			 		last = strTime.find(")");
			 		if(last == std::string::npos){
			 			break;
			 		}

			 		tempStrTime = strTime.substr(first+1 , last-1);
			 		timePrev = time;
			 		time = stod(tempStrTime);
			 		cout << line << endl;
			 		usleep((time - timePrev) * 1000000);
			 	}
			 }

			else{
				//signal(SIGINT, deleteFiles); //used to delete extracted files
				thread t1(video::playback_video, 0);		
				pcl::visualization::CloudViewer viewer("Sample_2.pcap");
				descr = pcap_open_offline("Sample_2.pcap", errbuf);
				if (descr == NULL) {
					cout << "pcap_open_offline() failed: " << errbuf << endl;
					return 1;
				}
				viewer.registerMouseCallback (mouseEventOccurred, (void*) &viewer);
				viewer.registerKeyboardCallback (keyboardEventOccurred, (void*) &viewer);
				viewer.runOnVisualizationThreadOnce (viewerOneOff);
				viewer.runOnVisualizationThread (viewerPsycho);
				pcap_loop(descr, 0, offline::packetHandler_II, (u_char *) &viewer);
				while(!viewer.wasStopped()){
						//do nothing
				}
				t1.join();
				int w = wait(NULL);
				int w1 = wait(NULL);	
			}
		}
	cout << "------------" << endl;
  	}
  	return 0;
}
