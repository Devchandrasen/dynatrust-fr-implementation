#include "../source/calibration-coverage.h"
#include <cassert>
#include <iostream>
int main(){
 calibration::Baseline b;for(double x:{-1.,0.,1.})b.Observe(x);
 assert(std::abs(b.Mean())<1e-12&&std::abs(b.SD()-1)<1e-12);
 sequential::Cusum c;for(int i=0;i<100;++i)c.Observe(i%2?1:-1,.5,8);
 assert(!c.Reject(8));for(int i=0;i<12;++i)c.Observe(1.5,.5,8);
 assert(c.Reject(8));for(int i=0;i<40;++i)c.Observe(0,.5,8);assert(!c.Reject(8));
 sequential::CommonEvent event;std::vector<double> common(24,55),minority(23,55);
 assert(!event.Observe(minority,36,1,2,3).available);
 assert(!event.Observe(common,36,2,2,3).available);
 assert(event.Observe(common,36,3,2,3).available);
 event.Reset();assert(!event.Observe(common,36,5,2,3).available);
 assert(!event.Observe(common,36,7,2,3).available); // Missing round breaks persistence.
 std::vector<double> split(18,45);split.insert(split.end(),18,63);
 assert(!event.Observe(split,36,8,2,3).available);
 // Greedy modular bonus changes the choice without admitting ineligible heads.
 std::vector<std::vector<double>> r={{2,1,5}};std::vector<bool> eligible={true,true,false};
 auto h=coverage::Greedy(r,eligible,1,{0,3,100});assert(h.size()==1&&h[0]==1);
 std::cout<<"Sequential, variance, consensus denominator, persistence and modular bonus tests passed\n";
}
