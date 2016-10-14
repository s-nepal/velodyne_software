# Makefile

CXX = g++
OFLAG = -O3 -Wno-deprecated -Wno-write-strings

CFLAGS = `pkg-config --cflags opencv`
LDFLAGS = `pkg-config --libs opencv`

all: main 

main: 
	@$(CXX) -std=c++11 -o main main.cpp $(OFLAG) \
	-I. -I/usr/include/pcap/ -I/usr/include/pcl-1.7 -I/usr/include/eigen3 \
	-I/usr/include/vtk-5.8 \
	-I/usr/lib/x86_64-linux-gnu/ \
	$(CFLAGS) $(LDFLAGS) \
	-rdynamic -lboost_system -lboost_filesystem -lboost_thread -lboost_date_time -lboost_iostreams \
	-lboost_serialization -lboost_chrono -lpthread -lpcl_common -Wl,-Bstatic -lflann_cpp_s -Wl,-Bdynamic \
	-lpcl_kdtree -lpcl_octree -lpcl_search -lqhull -lpcl_surface -lpcl_sample_consensus -lOpenNI -lOpenNI2 \
	-lpcl_io -lpcl_filters -lpcl_features -lpcl_keypoints -lpcl_registration -lpcl_segmentation -lpcl_recognition \
	-lpcl_visualization -lpcl_people -lpcl_outofcore -lpcl_tracking -lpcl_apps -lboost_system -lboost_filesystem \
	-lboost_thread -lboost_date_time -lboost_iostreams -lboost_serialization -lboost_chrono -lpthread -lqhull \
	-lOpenNI -lOpenNI2 -Wl,-Bstatic -lflann_cpp_s -Wl,-Bdynamic -lpcap \
	/usr/local/lib/libopencv_viz.so.3.1.0 /usr/local/lib/libopencv_videostab.so.3.1.0 \
	/usr/local/lib/libopencv_superres.so.3.1.0 /usr/local/lib/libopencv_stitching.so.3.1.0 \
	/usr/local/lib/libopencv_shape.so.3.1.0 /usr/local/lib/libopencv_photo.so.3.1.0 \
	/usr/local/lib/libopencv_objdetect.so.3.1.0 /usr/local/lib/libopencv_calib3d.so.3.1.0 \
	-lpthread -lpcl_common -lpcl_kdtree -lpcl_octree -lpcl_search -lpcl_surface -lpcl_sample_consensus \
	-lpcl_io -lpcl_filters -lpcl_features -lpcl_keypoints -lpcl_registration -lpcl_segmentation \
	-lpcl_recognition -lpcl_visualization -lpcl_people -lpcl_outofcore -lpcl_tracking -lpcl_apps -lpcap -lpthread \
	/usr/lib/libvtkGenericFiltering.so.5.8.0 /usr/lib/libvtkGeovis.so.5.8.0 /usr/lib/libvtkCharts.so.5.8.0 \
	/usr/lib/libvtkViews.so.5.8.0 /usr/lib/libvtkInfovis.so.5.8.0 /usr/lib/libvtkWidgets.so.5.8.0 \
	/usr/lib/libvtkVolumeRendering.so.5.8.0 /usr/lib/libvtkHybrid.so.5.8.0 /usr/lib/libvtkParallel.so.5.8.0 \
	/usr/lib/libvtkRendering.so.5.8.0 /usr/lib/libvtkImaging.so.5.8.0 /usr/lib/libvtkGraphics.so.5.8.0 \
	/usr/lib/libvtkIO.so.5.8.0 /usr/lib/libvtkFiltering.so.5.8.0 /usr/lib/libvtkCommon.so.5.8.0 \
	-lm /usr/lib/libvtksys.so.5.8.0 -ldl /usr/local/lib/libopencv_features2d.so.3.1.0 \
	/usr/local/lib/libopencv_ml.so.3.1.0 /usr/local/lib/libopencv_highgui.so.3.1.0 \
	/usr/local/lib/libopencv_videoio.so.3.1.0 /usr/local/lib/libopencv_imgcodecs.so.3.1.0 \
	/usr/local/lib/libopencv_flann.so.3.1.0 /usr/local/lib/libopencv_video.so.3.1.0 \
	/usr/local/lib/libopencv_imgproc.so.3.1.0 /usr/local/lib/libopencv_core.so.3.1.0 -Wl,-rpath,/usr/local/lib

#candump: lib
#	g++ -O2 -Wall -Wno-parentheses -fno-strict-aliasing -Iinclude -D_FILE_OFFSET_BITS=64 -DSO_RXQ_OVFL=40 -DPF_CAN=29 -DAF_CAN=PF_CAN  -c -o candump.o candump.cpp

#lib:
#	cc -O2 -Wall -Wno-parentheses -fno-strict-aliasing -Iinclude -D_FILE_OFFSET_BITS=64 -DSO_RXQ_OVFL=40 -DPF_CAN=29 -DAF_CAN=PF_CAN  -c -o lib.o lib.c

clean:
	rm -f main
	rm -f *.o
