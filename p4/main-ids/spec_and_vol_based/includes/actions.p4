#ifndef __ACTIONS__
#define __ACTIONS__

#include "headers.p4"

action drop(inout standard_metadata_t standard_metadata) 
{
    // set drop bit to 1
    standard_metadata.drop=1;
}

#endif