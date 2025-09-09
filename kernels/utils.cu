#include "utils.h"
#include <stdio.h>

extern "C" void gpu_init(int id) {
    cudaSetDevice(id);
    cudaDeviceReset();
    cudaDeviceSynchronize();
}