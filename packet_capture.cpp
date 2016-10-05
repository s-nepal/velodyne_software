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

using namespace std;
 
//Define the data structure builder function
//Input: 1248 byte long UDP data packet
//Output: Pointer to the data structure

volatile unsigned int pause_sim = 0;

void signalHandler1(int signum)
{
	pause_sim = 0;
	while(pause_sim == 0)
	{}
}

void signalHandler2(int signum)
{
	pause_sim = 1;
}


pcap_t *descr;
 
int main(int argc, char *argv[]) 
{	
	signal(SIGTSTP, signalHandler1);
	signal(SIGQUIT, signalHandler2);
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
			descr = pcap_open_live("eth0", 1248, 1, 1, errbuf);
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

			pcl::visualization::CloudViewer viewer("Data from eth1");
			std::thread t1(video::playback_video, 1);
			descr = pcap_open_live("eth1", 1248, 1, 1, errbuf);
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
		thread t1(video::capture_video);
		thread t2(record::save_pcap, "eth0", "Sample_1.pcap");
		thread t3(record::save_pcap, "eth1", "Sample_2.pcap");
		
		t2.join();
		t3.join();
		t1.join();
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
				video::playback_video(0);
			}

			else{

				//thread t1(video::playback_video, 0);
				pcl::visualization::CloudViewer viewer("Sample_2");
				viewer.runOnVisualizationThreadOnce (viewerOneOff);
				viewer.runOnVisualizationThread (viewerPsycho);
				offline::pcap_viewer_II((u_char *) &giant_vector_II, (u_char *) &viewer);
				//t1.join();
				while(!viewer.wasStopped()){
						//do nothing
  				}
  				int w = wait(NULL);
  			}
  			int w1 = wait(NULL);
		}
  	}
	cout << "------------" << endl;
  
  	return 0;
}
