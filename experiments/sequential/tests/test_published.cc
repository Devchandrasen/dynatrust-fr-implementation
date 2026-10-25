#include "../source/published-kernels.h"
#include <cassert>
#include <iostream>
int main(){
 // GTMS reference example: 50 successes, 60 failures -> rounded 45.
 assert(published::Gtms(50,60)==.45);assert(published::Gtms(0,0)==.5);
 assert(published::Gtms(10,0)==.91);
 assert(published::EdtmCommunication(0,0)==.5);
 assert(std::abs(published::EdtmCommunication(3,1)-.7)<1e-12);
 assert(published::LtmhlPenalty(.7,true)==.7);
 assert(std::abs(published::LtmhlPenalty(.7,false)-.6)<1e-12);
 published::Window w;w.observations={{1,true},{2,false}};
 auto [s,f]=w.Counts(61,60);assert(s==0&&f==1);
 std::cout<<"Published GTMS example, EDTM equation, LTMHL decrement and window expiry passed\n";
}
