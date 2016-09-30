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

#include "opencv2/opencv.hpp"

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <string>
#include <unistd.h>
#include <vector>
#include "data_structures.cpp"

#define PI 3.14159265
// list elevation angles corresponding to each of the 32 laser beams for the HDL-32
// const double elev_angles[32] = {-30.67, -9.33, -29.33, -8, -28, -6.66,
//         -26.66, -5.33, -25.33, -4, -24, -2.67, -22.67, -1.33, -21.33,
//         0, -20, 1.33, -18.67, 2.67, -17.33, 4, -16, 5.33, -14.67, 6.67,
//         -13.33, 8, -12, 9.33, -10.67, 10.67 };
// list elevation angles corresponding to each of the 16 laser beams for the VLP-16
const double elev_angles[32] = {-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15,-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15};


/* -------------------------------------------------------------
   -------------Structs needed to decode ethernet packets-------
   -------------------------------------------------------------*/

using namespace std;

int global_ctr = 0;		//to print out the packet number
const int cycle_num = 100;
const int delay_us = 90000;	
int user_data;


/* -------------------------------------------------------------*/
//Ancillary function for PCL
void viewerOneOff (pcl::visualization::PCLVisualizer& viewer)
{	
	viewer.setBackgroundColor (255,255,255); // black background
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

/* ------------------------------------------------------------*/

/* -------------------------------------------------------------
   -------------Capture video-----------------------------------
   -------------------------------------------------------------*/
namespace video
{
	void capture_video() //used only by record mode
	{	
		using namespace cv;
		VideoCapture cap(0); 	// open the default camera
		if(!cap.isOpened())		// check if we succeeded
	    	exit(0);
	    	
		Mat edges;
		//namedWindow("video",1);

		int frame_width = cap.get(CV_CAP_PROP_FRAME_WIDTH);
	   	int frame_height = cap.get(CV_CAP_PROP_FRAME_HEIGHT);

		VideoWriter video("out.avi",CV_FOURCC('M','J','P','G'),10, Size(frame_width,frame_height),true);

		for(;;){

	    	Mat frame;
	    	cap >> frame; 		// get a new frame from camera
	  
	    	video.write(frame);
	 
	    	//imshow("video", frame);
	    	
	    	if(waitKey(30) >= 0) break;
	   	}
	}

	void playback_video(int flag) //used by both the live mode and the offline mode
	{
		using namespace cv;
		VideoCapture cap;
		if(flag == 0) // offline mode
			cap.open("out.avi");
		else // live mode
			cap.open(0);
		
		if(!cap.isOpened())		// check if we succeeded
	    		return;
	    	
		Mat frame;
		namedWindow("video", 1);

		for(;;){	
	    	cap >> frame; 		// get a new frame from camera
	    	if(!frame.data) break;
	    	imshow("video", frame);
	    	if(waitKey(30) >= 0) break;
	   	}

	   	destroyWindow("video");

	}
}

/* ------------------------------------------------------------*/

/* -------------------------------------------------------------
   -------------data_structure_builder--------------------------
   -------------------------------------------------------------*/
namespace data_structure
{
	void data_structure_builder(const struct pcap_pkthdr *pkthdr, const u_char *data, struct data_packet& processed_packet)
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


	/* -------------------------------------------------------------
	   --------------------extract_xyz------------------------------
	   Input: processed_packet of data_packet struct
	   Output: Pointer to a cloud
	   Extracs x,y,z co-ordinates from processed packet and places in cloud pointer
	   -------------------------------------------------------------*/

	pcl::PointCloud<pcl::PointXYZRGBA>::Ptr extract_xyz(struct data_packet& processed_packet)
	{
		static pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);	
		pcl::PointXYZRGBA sample;

		for(int i = 0; i < 12; i++){
			double curr_azimuth = (processed_packet.payload[i].azimuth) * PI / 180; //convert degrees to radians
			for(int j = 0; j < 32; j++){
				double curr_dist = processed_packet.payload[i].dist[j];
				double curr_elev_angle = (elev_angles[j]) * PI / 180;
				sample.x = curr_dist * sin(curr_azimuth);
				sample.y = curr_dist * cos(curr_azimuth);
				sample.z = curr_dist * sin(curr_elev_angle);
				sample.r = 255; sample.g = 0; sample.b = 0;
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
			cout << "Error in reeading packets " << endl;
			exit(0);
		}
		
		cout << pcount <<" packets capture completed" << endl;
		pcap_dump_close(pd);
		pcap_close(descr1);

	}
}

namespace live
{
	void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
	{
		//assign the packaged ethernet data to the struct
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) userData;
		struct data_packet processed_packet;
		data_structure::data_structure_builder(pkthdr, packet, processed_packet);

		//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;
		cloud = data_structure::extract_xyz(processed_packet);

		if(global_ctr == cycle_num){ //buffer
			viewer->showCloud(cloud);
		}	
		
		//end the program if the viewer was closed by the user
		if(viewer->wasStopped()){
			cout << "Viewer Stopped" << endl;
			exit(0);
		}    
	}
}

namespace offline
{
	void pcap_copier(u_char *ptr_to_vector, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
	{
		vector<struct data_packet> *giant_vector = (vector<struct data_packet> *) ptr_to_vector;
		
		struct data_packet processed_packet;
		data_structure::data_structure_builder(pkthdr, packet, processed_packet);

		giant_vector -> push_back(processed_packet);
	}

	void pcap_viewer(u_char *ptr_to_vector, u_char *ptr_to_viewer)
	{	
		pcl::visualization::CloudViewer *viewer = (pcl::visualization::CloudViewer *) ptr_to_viewer;

		//pcl::visualization::CloudViewer viewer("Offline Mode");
		pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud;

		// viewer.runOnVisualizationThreadOnce (viewerOneOff);
		// viewer.runOnVisualizationThread (viewerPsycho);

		vector<struct data_packet> *giant_vector = (vector<struct data_packet> *) ptr_to_vector;
		struct data_packet curr_processed_packet;
		
		for(int i = 0; i < giant_vector -> size(); i++){
			curr_processed_packet = giant_vector -> at(i);
			cloud = data_structure::extract_xyz(curr_processed_packet);

			if(global_ctr == cycle_num){
				viewer->showCloud(cloud);
				usleep(delay_us);
			}

			if(viewer->wasStopped()){
				cout << "Viewer Stopped" << endl;
				exit(0);
			}
		}
	}

}



