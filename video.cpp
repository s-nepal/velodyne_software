#ifndef VIDEO_CPP
#define VIDEO_CPP
#include "opencv2/opencv.hpp"
#include "data_structures.h"
#include "defines.h"
#include <queue>
#include <string>

volatile unsigned int *pause_sim_kb = 0;
int exit_thread = false;
bool play_cloud = true;
/* ------------------------------------------------------------*/

/* -------------------------------------------------------------
   -------------Capture video-----------------------------------
   -------------------------------------------------------------*/
namespace video
{	
	std::queue<cv::Mat> video_buffer;	// buffer for video feed

	void capture_video() //used only by record mode
	{	
		using namespace cv;
		VideoCapture cap(camera_id); 	// open the default camera
		if(!cap.isOpened())		// check if we succeeded
	    	return;
	    	
		//Mat edges;
		//namedWindow("video",1);

		int frame_width = cap.get(CV_CAP_PROP_FRAME_WIDTH);
	   	int frame_height = cap.get(CV_CAP_PROP_FRAME_HEIGHT);

		VideoWriter video("out.avi",CV_FOURCC('M','J','P','G'),10, Size(frame_width,frame_height),true);

		for(;;){
			if(exit_thread == true){break;}	//return to main thread
	    	Mat frame;
	    	cap >> frame; 		// get a new frame from camera
	  
	    	video.write(frame);
	 
	    	if(waitKey(30) >= 0) break;
	   	}
	}

	void video_buffer_sender(cv::Mat frame, int frame_width, int frame_height)
	{	
		static int ctr = 0;
		using namespace cv;	
		video_buffer.push(frame);
		if(video_buffer.size() > num_frame_buffer_video){
			video_buffer.pop();

			// The following should only happen after a trigger is received
			std::string file_name = std::to_string(ctr++);	
			file_name = file_name + ".avi";
			VideoWriter video(file_name, CV_FOURCC('M','J','P','G'),10, Size(frame_width,frame_height),true);	
			while(!video_buffer.empty()){		
				video.write(video_buffer.front());
				video_buffer.pop();
				if(waitKey(30) >= 0) break;
			}
		}
	}

	void playback_video(int flag) //used by both the live mode and the offline mode
	{	
		using namespace cv;	

		bool playVideo = true;
		VideoCapture cap;
		if(flag == 0) // offline mode
			cap.open("out.avi");
		else // live mode
			cap.open(0);
		
		if(!cap.isOpened())		// check if we succeeded
	    	return;
	    
	    int frame_width = cap.get(CV_CAP_PROP_FRAME_WIDTH);
	   	int frame_height = cap.get(CV_CAP_PROP_FRAME_HEIGHT);

		Mat frame;
		namedWindow("video", 1);

		for(;;){	
			while(*pause_sim_kb == 1){}
			if(exit_thread){break;}
			if(playVideo)
	    		cap >> frame; // get a new frame from camera
 			
 			// Record video only if the code is in live mode
 			if(flag != 0)
	    		std::thread t1(video_buffer_sender, frame, frame_width, frame_height);

	    	if(!frame.data) break;
	    	imshow("video", frame);
	    	char key = waitKey(30);
        	if(key == 'p'){ //puase video playback if p is pressed
        		//Set here some kind of flag that also pauses cloud_viewer
            	playVideo = !playVideo;
            }
            if(flag != 0)
            	t1.join();
	   	}
	   	destroyWindow("video");
	}
}
#endif