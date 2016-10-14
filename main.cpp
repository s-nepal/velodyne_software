#include <iostream>
#include <assert.h>

#include <string>
#include <fstream>
#include <vector>
#include <stdlib.h>
#include <math.h>


#include <thread>
#include <sys/wait.h>

//#include "data_structures.cpp"
#include "functions.cpp"
#include <signal.h>
#include "lib.c"
#include "candump.cpp"
#include <fstream>

using namespace std;
 
//Define the data structure builder function
//Input: 1248 byte long UDP data packet
//Output: Pointer to the data structure

pcap_t *descr;
 
int main(int argc, char *argv[]) 
{	
	char *eth_port_1 = "eth0";
	char *eth_port_2 = "eth10";
	char *can_port = "vcan0";

	pause_sim_kb = (unsigned int *) mmap(NULL, sizeof (*pause_sim_kb), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	string s[3] = {"live", "record", "offline"};
	if(argc < 2)
	{
		cout << "input the proper option \n\t1)live\n\t2)record\n\t3)offline" << endl;
		exit(0);
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(argv[1] == s[0]) //live mode
	{	
		int pid = fork();
		if(pid < 0){
			cout << "fork error" << endl;
			exit(0);
		}
		
		// Create a fork to allow the data from 2 LiDAR's to be visualized in parallel
		else if(pid == 0){

			pcl::visualization::CloudViewer viewer("Data from eth0");
			descr = pcap_open_live(eth_port_1, 1248, 1, 1, errbuf);
				if (descr == NULL) {
					cout << "pcap_open_live() failed: " << errbuf << endl;
					return 1;
				}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
			viewer.runOnVisualizationThread (viewerPsycho);
			//loop through the pcap file and extract the packets
			pcap_loop(descr, 0, live::packetHandler_I, (u_char *) &viewer);

			while(!viewer.wasStopped()){
					//do nothing
			}
		}
		else {

				pcl::visualization::CloudViewer viewer("Data from eth10");
				std::thread t1(video::playback_video, 1);
				descr = pcap_open_live(eth_port_2, 1248, 1, 1, errbuf);
				if (descr == NULL) {
					cout << "pcap_open_live() failed: " << errbuf << endl;
					return 1;
				}
				viewer.runOnVisualizationThreadOnce (viewerOneOff);
				viewer.runOnVisualizationThread (viewerPsycho);
				pcap_loop(descr, 0, live::packetHandler_II, (u_char *) &viewer);
				int w = wait(NULL);
				t1.join();
				while(!viewer.wasStopped()){
					//do nothing
				}
			}
	}

	if(argv[1] == s[1]) // record mode
	{
		int ret = fork();
		if(ret < 0){
			cout << "fork error in record mode" << endl;
			exit(0);
		}
		else if(ret == 0){
			close(1);
			int fd = open("canData.txt", O_WRONLY | O_CREAT | O_TRUNC, 0660);
			if(fd < 0){
				cout << "cannot open file canData.txt" << endl;
				exit(0);
			}
			/*char *myargs[3];
			myargs[0] = (const char *) "candump";
			myargs[1] = (const char *) "can0";
			myargs[2] = NULL;
			int exec_return = execvp(myargs[0], myargs);
			*/

			char *myargv[4] = {"./candump", "-tz", can_port, NULL};
			int myargc = 3;
			int can_return = can_main(myargc, myargv);
			cout << "return from can_main function: " << can_return << endl;

		}
		else{
			thread t1(video::capture_video);
			thread t2(record::save_pcap, eth_port_1, "Sample_1.pcap");
			thread t3(record::save_pcap, eth_port_2, "Sample_2.pcap");

			t2.join();
			t3.join();
			t1.join();
			int w1 = wait(NULL);
		}
		
	}

	if(argv[1] == s[2]) // offline mode
	{
		cout << "Offline Mode Entered" << endl;

		// Fill 2 giant vectors with the contents of the 2 pcap files
		pcap_t *descr_I;
		pcap_t *descr_II;

		descr_I = pcap_open_offline("Sample_1.pcap", errbuf);
		if (descr_I == NULL) {
			cout << "pcap_open_offline() failed: " << errbuf << endl;
			return 1;
			}
			vector<struct data_packet> giant_vector_I;
			pcap_loop(descr_I, 0, offline::pcap_copier_I, (u_char *) &giant_vector_I);

			descr_II = pcap_open_offline("Sample_2.pcap", errbuf);	
			if (descr_II == NULL) {
			cout << "pcap_open_offline() failed: " << errbuf << endl;
			return 1;
			}
			vector<struct data_packet> giant_vector_II;	
			pcap_loop(descr_II, 0, offline::pcap_copier_II, (u_char *) &giant_vector_II);

			int pid = fork();
			if(pid < 0){
				cout << "fork error" << endl;
				exit(0);
			}

		else if(pid == 0){
			pcl::visualization::CloudViewer viewer("Sample_1");
			//viewer.registerMouseCallback (mouseEventOccurred, (void*) &viewer);
			viewer.registerKeyboardCallback (keyboardEventOccurred, (void*) &viewer);
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
			viewer.runOnVisualizationThread (viewerPsycho);
			offline::pcap_viewer_I((u_char *) &giant_vector_I, (u_char *) &viewer);

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
			 else if(pid1 == 0){
			 	
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

				thread t1(video::playback_video, 0);
				pcl::visualization::CloudViewer viewer("Sample_2");
				//viewer.registerMouseCallback (mouseEventOccurred, (void*) &viewer);
				viewer.registerKeyboardCallback (keyboardEventOccurred, (void*) &viewer);
				viewer.runOnVisualizationThreadOnce (viewerOneOff);
				viewer.runOnVisualizationThread (viewerPsycho);
				offline::pcap_viewer_II((u_char *) &giant_vector_II, (u_char *) &viewer);
				while(!viewer.wasStopped()){
						//do nothing
					}
				t1.join();
				int w = wait(NULL);	
			}
		}
	cout << "------------" << endl;
  	}
  	return 0;
}
