#define PI 3.14159265


const int camera_id = 0;

const int cycle_num_1 = 50; // Number of UDP packets per visualization frame (will change depending on HDL-64 spin rate)
const int delay_us_1 = 50000;	 // Number of microseconds to wait between frames
const int cycle_num_2 = 50; 
const int delay_us_2 = 50000;

// list elevation angles corresponding to each of the 32 laser beams for the HDL-32
// const double elev_angles[32] = {-30.67, -9.33, -29.33, -8, -28, -6.66,
//         -26.66, -5.33, -25.33, -4, -24, -2.67, -22.67, -1.33, -21.33,
//         0, -20, 1.33, -18.67, 2.67, -17.33, 4, -16, 5.33, -14.67, 6.67,
//         -13.33, 8, -12, 9.33, -10.67, 10.67 };
// list elevation angles corresponding to each of the 16 laser beams for the VLP-16
const double elev_angles[32] = {-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15,-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5,
								11, -3, 13, -1, 15};


char *eth_port_1 = "eth0";
char *eth_port_2 = "eth1"; // This will be a virtual port in the final version
char *eth_port_buffer_1 = "eth10"; // Virtual Port used to send buffer data from the first LiDAR
char *eth_port_buffer_2 = "eth11"; // for now only, later change to eth11; Virtual Port used to send buffer data from the second LiDAR
char *can_port = "vcan0";

const int num_frame_buffer_1 = 50; // Number of frames (360 deg) per LiDAR buffer 
const int num_frame_buffer_2 = 50;
const int num_frame_buffer_video = 50;

