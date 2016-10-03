#include "opencv2/opencv.hpp"
bool play_cloud = true;
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
		bool playVideo = true;
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
			if(playVideo)
	    		cap >> frame; // get a new frame from camera
	    	if(!frame.data) break;
	    	imshow("video", frame);
	    	char key = waitKey(30);
        	if(key == 'p'){ //puase video playback if p is pressed
        		//Set here some kind of flag that also pauses cloud_viewer
            	playVideo = !playVideo;
            }
           	//play_cloud = !play_cloud; 
	    	//if(waitKey(30) >= 0) break;
	   	}

	   	destroyWindow("video");

	}
}
