#ifndef FUNCTIONS_CPP
#define FUNCTIONS_CPP
#include <pcl/visualization/cloud_viewer.h>
#include <pcl/visualization/pcl_visualizer.h>
#include <pcl/io/io.h>
#include <pcl/io/pcd_io.h>
#include <pcl/point_types.h>
#include <pcl/filters/statistical_outlier_removal.h>
#include <pcl/filters/radius_outlier_removal.h>
#include <pcl/filters/passthrough.h>

#include <boost/thread/thread.hpp>
#include <pcl/common/common_headers.h>
#include <pcl/range_image/range_image.h>
#include <pcl/visualization/range_image_visualizer.h>



#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <string>
#include <unistd.h>
#include <vector>
#include <queue>

#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <iostream>

#include <sys/types.h>
#include <sys/mman.h>

#include "lib.c"
#include "candump.cpp"
#include "video.cpp"

// Includes for libtins
#include <tins/tins.h>

#define PI 3.14159265

using namespace std;

const double elev_angles[32] = {-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15,-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15};

const int cycle_num = 50; // Number of UDP packets per visualization frame (will change depending on HDL-64 spin rate)
const int delay_us = 50000;	 // Number of microseconds to wait between frames

int global_ctr = 0;		//to print out the packet number

int user_data;

queue<u_char*> buffer_1;

/* -------------------------------------------------------------
   -------------Functions to compress files into tar------------
   -------------------------------------------------------------*/
inline
void compressFunct(){
	if(system("tar -czvf data.tar.gz Sample_1.pcap Sample_2.pcap out.avi ") < 0){
	cout << "error in compressing files" << endl;
	exit(0);
	}
	if(system("rm Sample_1.pcap Sample_2.pcap out.avi") < 0){
		cout << "error in deleting pcap files" << endl;
		exit(0);
	}
}

void compressFiles(int signum){
	exit_thread = true;
	cout << "\nCompressing files into data.tar.gz file ..." << endl;
	sleep(1);
	compressFunct();
	exit(0);
}

void deleteFiles(int signum){
	exit_thread = true;
	cout << "\ndeleting pcap and video files" << endl;
	if( system("rm Sample_1.pcap Sample_2.pcap out.avi") < 0){
		cout << "error in deleting files" << endl;	
	}
	cout << "done!" << endl;
	exit(0);
}

inline
void canData(){
	char *myargv[4] = {"./candump", "-tz", "vcan0", NULL};
	int myargc = 3;
	int can_return = can_main(myargc, myargv);
	cout << "return from can_main function: " << can_return << endl;
}


/* -------------------------------------------------------------
   -------------Functions for user UI---------------------------
   -------------------------------------------------------------*/


void keyboardEventOccurred (const pcl::visualization::KeyboardEvent &event,
                            void* viewer_void)
{
  pcl::visualization::PCLVisualizer *viewer = static_cast<pcl::visualization::PCLVisualizer *> (viewer_void);
  if (event.getKeySym () == "space" && event.keyDown ())
  {
    if(*pause_sim_kb == 0){
    	*pause_sim_kb = 1;
    	std::cout << "Pausing the simulation " << std::endl;
    }
    else if(*pause_sim_kb == 1){
    	*pause_sim_kb = 0;
    }
  }
}


void mouseEventOccurred (const pcl::visualization::MouseEvent &event,
                         void* viewer_void)
{
  pcl::visualization::PCLVisualizer *viewer = static_cast<pcl::visualization::PCLVisualizer *> (viewer_void);
  if (event.getButton () == pcl::visualization::MouseEvent::LeftButton &&
      event.getType () == pcl::visualization::MouseEvent::MouseButtonPress)
  {
    //std::cout << "Left mouse button released at position (" << event.getX () << ", " << event.getY () << ")" << std::endl;

    char str[512];
    //sprintf (str, "text#%03d", text_id ++);
    //while(1){}
    //viewer->addText ("clicked here", event.getX (), event.getY (), str);
  }
}


/* -------------------------------------------------------------*/
//Ancillary function for PCL
void viewerOneOff (pcl::visualization::PCLVisualizer& viewer)
{	
	viewer.setBackgroundColor (255,255,255); // white background
	//viewer.setPointCloudRenderingProperties(pcl::visualization::PCL_VISUALIZER_POINT_SIZE,2); // size of point clouds
	viewer.setRepresentationToSurfaceForAllActors();
	viewer.addCoordinateSystem (2);
	viewer.initCameraParameters ();
	//viewer.setCameraPosition (0, 0, 100, 0, 0, 0);
	//viewer.resetCamera();
}

//Ancillary function for PCL
void viewerPsycho (pcl::visualization::PCLVisualizer& viewer)
{
	static unsigned count = 0;
   	std::stringstream ss;
	ss << "Once per viewer loop: " << count++;
	viewer.removeShape ("text", 0);
	user_data++;	
}

/* -------------------------------------------------------------
   -------------data_structure_builder--------------------------
   -------------------------------------------------------------*/
namespace data_structure
{
	void data_structure_builder_I(const struct pcap_pkthdr *pkthdr, const u_char *data, struct data_packet& processed_packet)
	{
	    //printf("Packet size: %d bytes\n", pkthdr->len);		
		if (pkthdr->len != pkthdr->caplen)
	    	printf("Warning! Capture size different than packet size: %ld bytes\n", (long)pkthdr->len);

		// return an empty struct if the packet length is not 1248 bytes
		if(pkthdr -> len != 1248){
			processed_packet = (const struct data_packet){0};
			return;
		}
				
		for(int i = 0; i < 42; i++){
			processed_packet.header[i] = data[i]; // fill in the header
		}

		//cout << endl;
		for(int i = 0; i < 6; i++){
			processed_packet.footer[i] = data[i + 1242]; // fill in the footer
		}

		// populate the payload (block ID, azimuth, 32 distances, 32 intensities  for each of the 12 data blocks)
		int curr_byte_index = 42; // not 43 bcz. in C++, indexing starts at 0, not 1
		uint8_t curr_firing_data[100];
		fire_data temp[12];

		for(int i = 0; i < 12; i++){
			for(int j = 0; j < 100; j++){
				curr_firing_data[j] = data[j + curr_byte_index];
			}
			temp[i].block_id = (curr_firing_data[1] << 8) | (curr_firing_data[0]);
			temp[i].azimuth = (double)((curr_firing_data[3] << 8) | (curr_firing_data[2])) / 100;

			int ctr = 0;
			for(int j = 0; j < 32; j++){
				temp[i].dist[j] = (double)((curr_firing_data[4 + ctr + 1] << 8) | curr_firing_data[4 + ctr]) / 500;
				temp[i].intensity[j] = curr_firing_data[4 + ctr + 2];
				ctr = ctr + 3;
			}
			processed_packet.payload[i] = temp[i];
			curr_byte_index = curr_byte_index + 100;
		}

		return;
	}

	void data_structure_builder_II(const struct pcap_pkthdr *pkthdr, const u_char *data, struct data_packet& processed_packet)
	{
	    //printf("Packet size: %d bytes\n", pkthdr->len);		
		if (pkthdr->len != pkthdr->caplen)
	    	printf("Warning! Capture size different than packet size: %ld bytes\n", (long)pkthdr->len);

		// // return an empty struct if the packet length is not 1248 bytes
		if(pkthdr -> len != 1248){
			processed_packet = (const struct data_packet){0};
			return;
		}
				
		for(int i = 0; i < 42; i++){
			processed_packet.header[i] = data[i]; // fill in the header
		}

		//cout << endl;
		for(int i = 0; i < 6; i++){
			processed_packet.footer[i] = data[i + 1242]; // fill in the footer
		}

		// populate the payload (block ID, azimuth, 32 distances, 32 intensities  for each of the 12 data blocks)
		int curr_byte_index = 42; // not 43 bcz. in C++, indexing starts at 0, not 1
		uint8_t curr_firing_data[100];
		fire_data temp[12];

		for(int i = 0; i < 12; i++){
			for(int j = 0; j < 100; j++){
				curr_firing_data[j] = data[j + curr_byte_index];
			}
			temp[i].block_id = (curr_firing_data[1] << 8) | (curr_firing_data[0]);
			temp[i].azimuth = (double)((curr_firing_data[3] << 8) | (curr_firing_data[2])) / 100;

			int ctr = 0;
			for(int j = 0; j < 32; j++){
				temp[i].dist[j] = (double)((curr_firing_data[4 + ctr + 1] << 8) | curr_firing_data[4 + ctr]) / 500;
				temp[i].intensity[j] = curr_firing_data[4 + ctr + 2];
				ctr = ctr + 3;
			}
			processed_packet.payload[i] = temp[i];
			curr_byte_index = curr_byte_index + 100;
		}

		return;
	}


	void colorize_point_cloud(double curr_intensity, pcl::PointXYZRGBA *sample)
	{	
		double intensity_range = 63; //any intensity value above 63 will be red
		double wavelength;

		if(curr_intensity <= 63)
			wavelength = curr_intensity / intensity_range * (780-380) + 380;
		else
			wavelength = 780;

		if((wavelength >= 380) && (wavelength<440)){
			sample->r = (-(wavelength - 440) / (440 - 380))*255;
			sample->g = 0;
			sample->b = 255;
			
		}else if((wavelength >= 440) && (wavelength<490)){
			sample->r = 0;
			sample->g = ((wavelength - 440) / (490 - 440))*255;
			sample->b = 255;
			
		}else if((wavelength >= 490) && (wavelength<510)){
			sample->r = 0;
			sample->g = 255;
			sample->b = (-(wavelength - 510) / (510 - 490))*255;
			
		}else if((wavelength >= 510) && (wavelength<580)){
			sample->r = ((wavelength - 510) / (580 - 510))*255;
			sample->g = 255;
			sample->b = 0;
			
		}else if((wavelength >= 580) && (wavelength<645)){
			sample->r = 255;
			sample->g = (-(wavelength - 645) / (645 - 580))*255;
			sample->b = 0;

		}else if((wavelength >= 645) && (wavelength<781)){
			sample->r = 255;
			sample->g = 0;
			sample->b = 0;
		}else{
			sample->r = 0;
			sample->g = 0;
			sample->b = 0;
		}
	}

	/* -------------------------------------------------------------
	   --------------------extract_xyz------------------------------
	   Input: processed_packet of data_packet struct
	   Output: Pointer to a cloud
	   Extracs x,y,z co-ordinates from processed packet and places in cloud pointer
	   -------------------------------------------------------------*/

	pcl::PointCloud<pcl::PointXYZRGBA>::Ptr extract_xyz_I(struct data_packet& processed_packet)
	{
		static pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);	
		pcl::PointXYZRGBA sample;

		for(int i = 0; i < 12; i++){
			double curr_azimuth = (processed_packet.payload[i].azimuth) * PI / 180; //convert degrees to radians
			for(int j = 0; j < 32; j++){
				double curr_dist = processed_packet.payload[i].dist[j];
				double curr_intensity = processed_packet.payload[i].intensity[j];
				double curr_elev_angle = (elev_angles[j]) * PI / 180;
				sample.x = curr_dist * sin(curr_azimuth);
				sample.y = curr_dist * cos(curr_azimuth);
				sample.z = curr_dist * sin(curr_elev_angle);
				//call function to colorize the point cloud
				colorize_point_cloud(curr_intensity, &sample);
				cloud -> points.push_back(sample);
			}
		}

		if(global_ctr > cycle_num){
			cloud -> points.clear();
			global_ctr = 0;
			//usleep(400000); //0.1s delay
		}
		global_ctr++;

		return cloud;
	}

	pcl::PointCloud<pcl::PointXYZRGBA>::Ptr extract_xyz_II(struct data_packet& processed_packet)
	{
		static pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);	
		pcl::PointXYZRGBA sample;

		for(int i = 0; i < 12; i++){
			double curr_azimuth = (processed_packet.payload[i].azimuth) * PI / 180; //convert degrees to radians
			for(int j = 0; j < 32; j++){
				double curr_dist = processed_packet.payload[i].dist[j];
				double curr_intensity = processed_packet.payload[i].intensity[j];
				double curr_elev_angle = (elev_angles[j]) * PI / 180;
				sample.x = curr_dist * sin(curr_azimuth);
				sample.y = curr_dist * cos(curr_azimuth);
				sample.z = curr_dist * sin(curr_elev_angle);
				//call function to colorize the point cloud
				colorize_point_cloud(curr_intensity, &sample);
				cloud -> points.push_back(sample);
			}
		}

		if(global_ctr > cycle_num){
			cloud -> points.clear();
			global_ctr = 0;
			//usleep(400000); //0.1s delay
		}
		global_ctr++;

		return cloud;
	}

}

namespace live
{	
	void buffer_sender(const u_char *packet)
	{
		int ctr = 42;
		
		char temp_packet[1206];
		for(int i =0; i < 1206; i++){
			temp_packet[i] = packet[ctr]; // This is where the equavalence between u_char and char happens.
			ctr++;
		}
		
		string pkt_buffer;

		for(int i = 0; i < 1206; i++){
			pkt_buffer.append(1, temp_packet[i]);
		}
		// pkt_buffer(temp_packet, 1206);
		//cout << sizeof(temp_packet) / sizeof(temp_packet[0]);
		
		// craft a string from the array of u_char stored in packet
		// The second argument evaluates to 1206
   		//pkt_buffer(temp_packet, temp_packet + sizeof temp_packet / sizeof temp_packet[0]);

   		//cout << pkt_buffer << endl << "****************" << endl;

   		// char experiment[pkt_buffer.size() + 1];
   		// strcpy(experiment, pkt_buffer.c_str());

   		// cout << "Final" << endl;
   		// for(int i = 0; i < 4; i++){
   		// 	//printf("%08X\n", experiment[i]);
   		// 	cout << experiment[i] << endl;
   		// 	//printf("%02X\n", temp_packet[i]);
   		// }

   		// cout << "****************" << endl;

   		//cout << pkt_buffer << endl;
   		//cout << "****************************" << endl;
   		
   		static Tins::PacketSender sender;
   		static Tins::NetworkInterface iface("eth10");

		//if(buffer_1.size() == 5){
			//while(!buffer_1.empty()){
				//Tins::EthernetII pkt = Tins::EthernetII() / Tins::IP("255.255.255.255") / Tins::UDP() /  
					//Tins::RawPDU((char*)buffer_1.back());
				Tins::EthernetII pkt = Tins::EthernetII() / Tins::IP("255.255.255.255") / Tins::UDP() /  
					Tins::RawPDU(pkt_buffer);
				sender.send(pkt, iface); // send it through eth0
				buffer_1.pop();
			//}
		//}
	}

	void packetHandler_I(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char *packet) 
	{
		//assign the packaged ethernet data to the struct
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) userData;
		struct data_packet processed_packet;
		data_structure::data_structure_builder_I(pkthdr, packet, processed_packet);

		u_char *s = new u_char [1248];
		for(int i = 0; i < 1248; i++){
			s[i] = packet[i];
			//printf("%02X\n", packet[i]);
		}

		buffer_1.push(s);

		if(buffer_1.size() > 5){
			buffer_1.pop();
		}

		u_char *packet_II = new u_char [100];
		u_char first = 'a'; u_char second = 'b'; u_char third = 'c'; 
		for(int i = 0; i < 100; i++){
			if(i == 0)
				packet_II[i] = first;
			if(i == 1)
				packet_II[i] = second;
			if(i == 2)
				packet_II[i] = third;
			if(i == 3)
				packet_II[i] = third;
			if(i > 3)
				packet_II[i] = third;
		}
		
		// for(int i = 0; i < 100; i++){
		// 	cout << packet_II[i] << endl;
		// }

		// cout << "****************" << endl;

		// int ctr = 42;
		// for(int i = 0; i < 1206; i++){
		// 	//printf("%08X\n", packet[ctr]);
		// 	ctr++;
		// }

		//cout << "****************************" << endl;


		// int ctr = 42;
		
		// //char *temp_packet = new char[4]; 
		// char temp_packet[1206];
		// for(int i =0; i < 1206; i++){
		// 	temp_packet[i] = packet[ctr];
		// 	ctr++;
		// }
		
		thread t1(buffer_sender, packet);	

		//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;
		cloud = data_structure::extract_xyz_I(processed_packet);

		if(global_ctr == cycle_num){ //buffer
			viewer->showCloud(cloud);
		}	
		
		//end the program if the viewer was closed by the user
		if(viewer->wasStopped()){
			//cout << "Viewer Stopped" << endl;
			//exit(0);
			return;
		}

		t1.join();  
	}

	void packetHandler_II(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
	{
		//assign the packaged ethernet data to the struct
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) userData;
		struct data_packet processed_packet;
		data_structure::data_structure_builder_II(pkthdr, packet, processed_packet);

		//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;
		cloud = data_structure::extract_xyz_II(processed_packet);

		if(global_ctr == cycle_num){ //buffer
			viewer->showCloud(cloud);
		}	
		
		//end the program if the viewer was closed by the user
		if(viewer->wasStopped()){
			//cout << "Viewer Stopped" << endl;
			//exit(0);	//disabled temporarily; making child exit which makes parent to wait for child forever;
			return;
		}    
	}
}


/* -------------------------------------------------------------
   -------Saving the data into pcap file------------------------
   open capture file for offline processing can be done by
   descr = pcap_open_offline("Sample_1.pcap", errbuf);
   -------------------------------------------------------------*/
namespace record
{
	void save_pcap( const char *port, const char *file_name)
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_dumper_t *pd;
		pcap_t *descr1;
		descr1 = pcap_open_live(port, 1248, 1, 1, errbuf);

		if (descr1 == NULL) {
			cout << "pcap_open_live() failed: " << errbuf << endl;
			exit(0);
		}
		
		cout << "Saving the data into " << file_name << endl;
		
		if((pd = pcap_dump_open(descr1, file_name)) == NULL){
			cout << "error in opening file Sample_2.pcap" << endl;
			exit(0);
		}
		
		int pcount;
		//usleep(100000);
		if((pcount = pcap_loop(descr1, 0, &pcap_dump, (u_char *) pd)) < 0){
			cout << "Error in reading packets " << endl;
			exit(0);
		}
		
		cout << pcount <<" packets capture completed" << endl;
		pcap_dump_close(pd);
		pcap_close(descr1);

	}
}

namespace offline
{	
	void packetHandler_I(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
	{	
		while(*pause_sim_kb == 1){}
		//assign the packaged ethernet data to the struct
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) userData;
		struct data_packet processed_packet;
		data_structure::data_structure_builder_I(pkthdr, packet, processed_packet);

		//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;
		cloud = data_structure::extract_xyz_I(processed_packet);

		if(global_ctr == cycle_num){ //buffer
			viewer->showCloud(cloud);
			usleep(delay_us);
		}	
		
		//end the program if the viewer was closed by the user
		if(viewer->wasStopped()){
			//cout << "Viewer Stopped" << endl;
			//exit(0);
			return;
		}    
	}

	void packetHandler_II(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
	{	
		while(*pause_sim_kb == 1){}
		//assign the packaged ethernet data to the struct
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) userData;
		struct data_packet processed_packet;
		data_structure::data_structure_builder_II(pkthdr, packet, processed_packet);

		//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;
		cloud = data_structure::extract_xyz_II(processed_packet);

		if(global_ctr == cycle_num){ //buffer
			viewer->showCloud(cloud);
			usleep(delay_us);
		}	
		
		//end the program if the viewer was closed by the user
		if(viewer->wasStopped()){
			//cout << "Viewer Stopped" << endl;
			//exit(0);	//disabled temporarily; making child exit which makes parent to wait for child forever;
			return;
		}    
	}

}

#endif


