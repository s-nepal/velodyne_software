#include <iostream>
#include <assert.h>

#include "functions.cpp"

#include <string>
#include <fstream>
#include <vector>
#include <stdlib.h>
#include <math.h>


#include <thread>
#include <sys/wait.h>

using namespace std;
 
pcap_t *descr;
 
int main(int argc, char *argv[]) 
{		
	string s[3] = {"live", "record", "offline"}; // 3 modes that the program can operate in
	if(argc < 2){
		cout << "input the proper option \n\t1)live\n\t2)record\n\t3)offline" << endl;
		exit(0);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(argv[1] == s[0]){  //live mode	
		int pid = fork();
		if(pid < 0){
			cout << "fork error" << endl;
			exit(0);
		}
		
		// Create a fork to allow the data from 2 LiDAR's to be visualized in parallel
		else if(pid == 0){
			pcl::visualization::CloudViewer viewer("Data from eth0");
			descr = pcap_open_live("eth0", 1248, 1, 1, errbuf); //open eth0 Ethernet port to receive UDP data packets
  			if (descr == NULL) {
 				cout << "pcap_open_live() failed: " << errbuf << endl;
 				return 1;
  			}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
    		viewer.runOnVisualizationThread (viewerPsycho);
    		//loop through the UDP stream to extract UDP data packets
    		pcap_loop(descr, 0, packetHandler, (u_char *) &viewer);
 
			while(!viewer.wasStopped()){
  				//do nothing
  			}
		} else {

			pcl::visualization::CloudViewer viewer("Data from eth1"); //open eth1 Ethernet port to receive UDP data packets
			std::thread t1(playback_video, 1); //introduce a thread for simultaneous capture of video feed from the camera
			descr = pcap_open_live("eth1", 1248, 1, 1, errbuf);
			if (descr == NULL) {
				cout << "pcap_open_live() failed: " << errbuf << endl;
				return 1;
			}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
		    viewer.runOnVisualizationThread (viewerPsycho);
		    pcap_loop(descr, 0, packetHandler, (u_char *) &viewer);
			int w = wait(NULL);
			t1.join();
			while(!viewer.wasStopped()){
				//do nothing
			}
  		}
	}

	if(argv[1] == s[1]) { //record mode
		std::thread t1(capture_video);
		std::thread t2(save_pcap, "eth0", "Sample_1.pcap");
		std::thread t3(save_pcap, "eth1", "Sample_2.pcap");
		
		t2.join();
		t3.join();
		t1.join();
	}
	
	if(argv[1] == s[2]) { //offline mode
		int pid = fork();
		if(pid < 0){
			cout << "fork error" << endl;
			exit(0);
		}
		
		else if(pid == 0){ // first fork to visualize Sample_1.pcap
			pcl::visualization::CloudViewer viewer("Sample_1");
			descr = pcap_open_offline("Sample_1.pcap", errbuf);
  			if (descr == NULL) {
 				cout << "pcap_open_offline() failed: " << errbuf << endl;
 				return 1;
  			}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
    		viewer.runOnVisualizationThread (viewerPsycho);
    		//loop through the pcap file and extract the packets
    		pcap_loop(descr, 0, packetHandler, (u_char *) &viewer);

			while(!viewer.wasStopped()){
  				//do nothing
  			}
  			
		} else { // second fork to visualize Sample_2.pcap
			pcl::visualization::CloudViewer viewer("Sample_2");
			std::thread t1(playback_video, 0);
			descr = pcap_open_offline("Sample_2.pcap", errbuf);
			if (descr == NULL) {
				cout << "pcap_open_offline() failed: " << errbuf << endl;
				return 1;
			}
			viewer.runOnVisualizationThreadOnce (viewerOneOff);
	    	viewer.runOnVisualizationThread (viewerPsycho);
	    	pcap_loop(descr, 0, packetHandler, (u_char *) &viewer);
			int w = wait(NULL);
			t1.join();
			while(!viewer.wasStopped()){
				//do nothing
			}
  		}

	}	
	cout << "------------" << endl;
  
  	return 0;
}
